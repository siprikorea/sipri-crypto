package com.siprikorea.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAValidationParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;

/**
 * KCDSA domain parameter generation following TTAK.KO-12.0001/R4 sec. 5.1 and Appendix I:
 * p = 2Jq + 1 where J and q are derived from a seed through the PPGF hash-based pseudo-random
 * generator, so that the (seed, count) pair recorded in the result's
 * {@link DSAValidationParameters} lets a third party re-derive and validate p and q.
 * <p>
 * Generating 2048- and 3072-bit parameters takes a noticeable amount of time (seconds to minutes);
 * where possible generate once and distribute the parameters.
 * </p>
 */
public class KCDSAParametersGenerator
{
    private static final int MR_CERTAINTY = 128;
    private static final int MAX_COUNT = 1 << 24;

    private final Digest digest;

    private int alpha;
    private int beta;
    private SecureRandom random;

    /**
     * @param digest the hash function used by PPGF - the hash of the KCDSA parameter set
     *               (SHA-224 for (2048, 224, SHA-224), SHA-256 otherwise, HAS-160 for legacy 1024).
     */
    public KCDSAParametersGenerator(Digest digest)
    {
        this.digest = digest;
    }

    /**
     * @param alpha  the bit length of p.
     * @param beta   the bit length of q.
     * @param random source of the seed and of h.
     */
    public void init(int alpha, int beta, SecureRandom random)
    {
        if (beta < 160 || alpha < beta + 64)
        {
            throw new IllegalArgumentException("invalid KCDSA (|p|, |q|) = (" + alpha + ", " + beta + ")");
        }

        this.alpha = alpha;
        this.beta = beta;
        this.random = CryptoServicesRegistrar.getSecureRandom(random);
    }

    public DSAParameters generateParameters()
    {
        byte[] seed = new byte[(beta + 7) / 8];

        for (;;)
        {
            random.nextBytes(seed);

            BigInteger j = generateJ(digest, seed, alpha, beta);
            if (j == null)
            {
                continue;
            }

            for (int count = 1; count <= MAX_COUNT; ++count)
            {
                BigInteger[] pq = generatePQ(digest, seed, j, count, alpha, beta);
                if (pq != null)
                {
                    BigInteger g = generateG(pq[0], j, random);

                    return new DSAParameters(pq[0], pq[1], g, new DSAValidationParameters(Arrays.clone(seed), count));
                }
            }
        }
    }

    /**
     * Steps 2-4: J = 2^(alpha-beta-1) | PPGF(seed, alpha-beta-4) | 1.
     *
     * @return J, or null if the candidate is not prime (choose a new seed).
     */
    public static BigInteger generateJ(Digest digest, byte[] seed, int alpha, int beta)
    {
        int n = alpha - beta - 4;
        BigInteger j = new BigInteger(1, ppgf(digest, n, seed))
            .setBit(0).setBit(alpha - beta - 1);

        return j.isProbablePrime(MR_CERTAINTY) ? j : null;
    }

    /**
     * Steps 8-12 for a single count value: q = 2^(beta-1) | PPGF(seed || count, beta) | 1,
     * p = 2Jq + 1.
     *
     * @return {p, q}, or null if this count does not yield primes of the right size.
     */
    public static BigInteger[] generatePQ(Digest digest, byte[] seed, BigInteger j, int count, int alpha, int beta)
    {
        byte[] input = Arrays.concatenate(seed, Pack.intToBigEndian(count));
        BigInteger q = new BigInteger(1, ppgf(digest, beta, input)).setBit(0).setBit(beta - 1);
        BigInteger p = j.multiply(q).shiftLeft(1).add(BigInteger.ONE);

        if (p.bitLength() > alpha || !q.isProbablePrime(MR_CERTAINTY) || !p.isProbablePrime(MR_CERTAINTY))
        {
            return null;
        }

        return new BigInteger[]{ p, q };
    }

    /**
     * g = h^(2J) mod p for a random 1 &lt; h &lt; p - 1, retried until g != 1.
     */
    public static BigInteger generateG(BigInteger p, BigInteger j, SecureRandom random)
    {
        BigInteger e = j.shiftLeft(1);
        BigInteger two = BigInteger.valueOf(2);

        for (;;)
        {
            BigInteger h = BigIntegers.createRandomInRange(two, p.subtract(two), random);
            BigInteger g = h.modPow(e, p);
            if (!g.equals(BigInteger.ONE))
            {
                return g;
            }
        }
    }

    /**
     * PPGF (TTAK.KO-12.0001/R4 Appendix I): the rightmost {@code nBits} bits of
     * {@code ... || Hash(src || 1) || Hash(src || 0)}, the counter being a single byte.
     */
    static byte[] ppgf(Digest digest, int nBits, byte[] src)
    {
        int len = (nBits + 7) / 8;
        int lh = digest.getDigestSize();
        byte[] out = new byte[len];
        byte[] h = new byte[lh];

        int i = len;
        for (int ctr = 0; ; ++ctr)
        {
            digest.reset();
            digest.update(src, 0, src.length);
            digest.update((byte)ctr);
            digest.doFinal(h, 0);

            if (i >= lh)
            {
                i -= lh;
                System.arraycopy(h, 0, out, i, lh);
                if (i == 0)
                {
                    break;
                }
            }
            else
            {
                System.arraycopy(h, lh - i, out, 0, i);
                break;
            }
        }

        int excess = len * 8 - nBits;
        if (excess > 0)
        {
            out[0] &= (byte)(0xFF >>> excess);
        }

        return out;
    }
}
