# sipri/ - Sipri Crypto module

This module is the whole of Sipri Crypto's own code: the Korean algorithms (KCDSA, EC-KCDSA, LSH,
HIGHT, HAS-160) and the `SipriCrypto` JCA/JCE provider, in `com.siprikorea.crypto`. The rest of the
repository is unmodified Bouncy Castle tracked from bcgit/bc-java; read `../SIPRI.md` first.

- **Never edit `org.bouncycastle` sources to support Sipri work.** Every path that differs from
  upstream must be listed in `../.sipri-overlay`, and `../scripts/sync-upstream.sh --check` (run by
  CI) fails otherwise. Upstream edits are what make the weekly upstream merge conflict.
  Use BC's public API (`BaseBlockCipher`, `BCMessageDigest`, `DSAUtil`, `ECUtil`, `KeyUtil`, ...)
  from here instead; if something needed is package-private, copy the small piece into this module.
- The root `../CLAUDE.md` conventions still apply here (Allman braces enforced by
  `:sipri:checkstyleMain`, `SecurityExceptions` factories, `Signature.verify()` returns false for
  malformed input, `setParameter` throws only `InvalidAlgorithmParameterException`, AllTests
  returns a `TestSetup`).
- Run: `JAVA_HOME=<jdk25> ./gradlew :prov:compileJava :sipri:cleanTest :sipri:test`. Results land
  in `sipri/build/test-results/TEST-*.xml`; check they are fresh.
- New algorithms need known-answer tests from a published source (standard appendix or an
  independent implementation's vectors) registered in `com.siprikorea.crypto.test.AllTests`, and a
  mutation check (break the implementation, confirm the KAT fails). Self round trips alone are not
  evidence. Adding a provider service means updating the service count in
  `ProviderTest.testAllServicesResolve`.
- KCDSA keys are `y = g^(x^-1 mod q) mod p` and EC-KCDSA keys `Q = d^-1 G` - not DSA/ECDSA keys.
