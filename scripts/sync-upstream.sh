#!/usr/bin/env bash
#
# Merge the latest Bouncy Castle (bcgit/bc-java) into Sipri Crypto.
#
#   scripts/sync-upstream.sh [options]
#
#   --branch NAME   merge on a new branch NAME (default: sync/upstream-<date>); "--branch ."
#                   merges into the current branch
#   --ref REF       upstream ref to merge (default: upstream/main; e.g. a release tag r1rv87)
#   --test          after merging, compile prov and run the sipri test suite
#   --push          push the branch to origin
#   --pr            push and open a pull request with gh
#   --check         only report: commits behind upstream and overlay drift, change nothing
#
# On a conflict the merge is left in progress so it can be resolved by hand; finish with
# "git add ... && git commit", then re-run with --check to confirm the overlay is still clean.
# The script exits 0 with nothing to do when already up to date.
#
set -euo pipefail

UPSTREAM_URL="https://github.com/bcgit/bc-java.git"
REF="upstream/main"
BRANCH="sync/upstream-$(date +%Y%m%d)"
RUN_TESTS=0
PUSH=0
OPEN_PR=0
CHECK_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --branch) BRANCH="$2"; shift 2 ;;
        --ref) REF="$2"; shift 2 ;;
        --test) RUN_TESTS=1; shift ;;
        --push) PUSH=1; shift ;;
        --pr) PUSH=1; OPEN_PR=1; shift ;;
        --check) CHECK_ONLY=1; shift ;;
        -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

cd "$(git rev-parse --show-toplevel)"

# --- remote and attributes -------------------------------------------------------------------

if ! git remote get-url upstream >/dev/null 2>&1; then
    echo ">> adding remote upstream -> $UPSTREAM_URL"
    git remote add upstream "$UPSTREAM_URL"
fi

# settings.gradle only ever gains include lines on both sides, so let git keep both sides'
# additions rather than conflict. Written to .git/info/attributes (local, untracked) so that the
# upstream-owned .gitattributes stays untouched.
ATTR="$(git rev-parse --git-path info/attributes)"
mkdir -p "$(dirname "$ATTR")"
grep -qx 'settings.gradle merge=union' "$ATTR" 2>/dev/null || echo 'settings.gradle merge=union' >> "$ATTR"

echo ">> fetching upstream"
git fetch --quiet --tags upstream

# --- overlay drift check -----------------------------------------------------------------------

# Paths that differ between HEAD and the upstream ref and are not covered by .sipri-overlay.
drift_report() {
    local base="$1" pathspecs=() line
    while IFS= read -r line; do
        line="${line%%#*}"; line="$(echo "$line" | xargs)"
        [ -n "$line" ] && pathspecs+=(":(glob,exclude)$line")
    done < .sipri-overlay
    git diff --name-only "$base" HEAD -- . "${pathspecs[@]}"
}

check_drift() {
    local drift
    drift="$(drift_report "$1")"
    if [ -n "$drift" ]; then
        echo "!! these paths differ from $1 but are not in .sipri-overlay:" >&2
        echo "$drift" | sed 's/^/     /' >&2
        echo "   Move the change into sipri/, or list the path in .sipri-overlay if it is intended." >&2
        return 1
    fi
    echo ">> overlay clean: only .sipri-overlay paths differ from $1"
}

BEHIND="$(git rev-list --count "HEAD..$REF")"
echo ">> $BEHIND upstream commit(s) not yet merged from $REF ($(git rev-parse --short "$REF"))"

if [ "$CHECK_ONLY" = 1 ]; then
    # compare with the merge base, so unmerged upstream work does not count as drift
    check_drift "$(git merge-base HEAD "$REF")"
    exit $?
fi

if [ "$BEHIND" = 0 ]; then
    echo ">> already up to date"
    exit 0
fi

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "!! working tree has uncommitted changes; commit or stash them first" >&2
    exit 1
fi

# --- merge -------------------------------------------------------------------------------------

if [ "$BRANCH" != "." ]; then
    echo ">> creating branch $BRANCH"
    git switch -c "$BRANCH"
fi

UPSTREAM_SHA="$(git rev-parse --short "$REF")"
if ! git merge --no-ff --no-edit -m "Merge upstream Bouncy Castle $REF ($UPSTREAM_SHA) into Sipri Crypto" "$REF"; then
    echo >&2
    echo "!! merge conflicts:" >&2
    git diff --name-only --diff-filter=U | sed 's/^/     /' >&2
    echo "   Resolve them, 'git add' the files and 'git commit', then run: $0 --check" >&2
    echo "   (For upstream files, prefer upstream's version - Sipri code belongs in sipri/.)" >&2
    exit 1
fi

check_drift "$REF"

# --- verify ------------------------------------------------------------------------------------

if [ "$RUN_TESTS" = 1 ]; then
    echo ">> compiling prov and running the sipri test suite"
    ./gradlew --console=plain :prov:compileJava :sipri:cleanTest :sipri:test :sipri:checkstyleMain
fi

# --- publish -----------------------------------------------------------------------------------

if [ "$PUSH" = 1 ]; then
    git push -u origin HEAD
fi

if [ "$OPEN_PR" = 1 ]; then
    gh pr create --base main --head "$(git branch --show-current)" \
        --title "Merge upstream Bouncy Castle ($UPSTREAM_SHA)" \
        --body "Merges $BEHIND commit(s) from bcgit/bc-java \`$REF\` (\`$UPSTREAM_SHA\`).

Generated by \`scripts/sync-upstream.sh\`. The overlay check passed: only paths listed in \`.sipri-overlay\` differ from upstream."
fi

echo ">> done"
