package com.siprikorea.crypto.digests;

import org.bouncycastle.crypto.CryptoServiceProperties;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * HAS-160 hash function (TTAS.KO-12.0011/R2), the 160-bit hash originally specified for use with
 * KCDSA.
 * <p>
 * <b>Legacy algorithm.</b> HAS-160 is no longer an approved hash in the Korean Cryptographic
 * Module Validation Program; it is provided to verify and interoperate with existing
 * HAS160withKCDSA signatures. New designs should use SHA-2 or LSH.
 * </p>
 */
public class HAS160Digest
    extends GeneralDigest
{
    private static final int DIGEST_LENGTH = 20;

    private static final int[] S1 = { 5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13 };

    // message word order per round; indices 16..19 are the per-round XOR words
    private static final int[][] L = {
        { 18, 0, 1, 2, 3, 19, 4, 5, 6, 7, 16, 8, 9, 10, 11, 17, 12, 13, 14, 15 },
        { 18, 3, 6, 9, 12, 19, 15, 2, 5, 8, 16, 11, 14, 1, 4, 17, 7, 10, 13, 0 },
        { 18, 12, 5, 14, 7, 19, 0, 9, 2, 11, 16, 4, 13, 6, 15, 17, 8, 1, 10, 3 },
        { 18, 7, 2, 13, 8, 19, 3, 14, 9, 4, 16, 15, 10, 5, 0, 17, 11, 6, 1, 12 }
    };

    // the four message words XORed together for X[16..19], per round
    private static final int[][][] XW = {
        { { 0, 1, 2, 3 }, { 4, 5, 6, 7 }, { 8, 9, 10, 11 }, { 12, 13, 14, 15 } },
        { { 3, 6, 9, 12 }, { 2, 5, 8, 15 }, { 1, 4, 11, 14 }, { 0, 7, 10, 13 } },
        { { 5, 7, 12, 14 }, { 0, 2, 9, 11 }, { 4, 6, 13, 15 }, { 1, 3, 8, 10 } },
        { { 2, 7, 8, 13 }, { 3, 4, 9, 14 }, { 0, 5, 10, 15 }, { 1, 6, 11, 12 } }
    };

    private static final int[] K = { 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc };
    private static final int[] S2 = { 10, 17, 25, 30 };

    private int h0, h1, h2, h3, h4;

    private final int[] x = new int[20];
    private int xOff;

    public HAS160Digest()
    {
        this(CryptoServicePurpose.ANY);
    }

    public HAS160Digest(CryptoServicePurpose purpose)
    {
        super(purpose);

        reset();
    }

    /**
     * Copy constructor.
     *
     * @param t the digest whose state is copied.
     */
    public HAS160Digest(HAS160Digest t)
    {
        super(t);

        copyState(t);
    }

    private void copyState(HAS160Digest t)
    {
        super.copyIn(t);

        h0 = t.h0;
        h1 = t.h1;
        h2 = t.h2;
        h3 = t.h3;
        h4 = t.h4;

        System.arraycopy(t.x, 0, x, 0, x.length);
        xOff = t.xOff;
    }

    public String getAlgorithmName()
    {
        return "HAS-160";
    }

    public int getDigestSize()
    {
        return DIGEST_LENGTH;
    }

    protected void processWord(byte[] in, int inOff)
    {
        x[xOff++] = Pack.littleEndianToInt(in, inOff);

        if (xOff == 16)
        {
            processBlock();
        }
    }

    protected void processLength(long bitLength)
    {
        if (xOff > 14)
        {
            processBlock();
        }

        x[14] = (int)bitLength;
        x[15] = (int)(bitLength >>> 32);
    }

    public int doFinal(byte[] out, int outOff)
    {
        finish();

        Pack.intToLittleEndian(h0, out, outOff);
        Pack.intToLittleEndian(h1, out, outOff + 4);
        Pack.intToLittleEndian(h2, out, outOff + 8);
        Pack.intToLittleEndian(h3, out, outOff + 12);
        Pack.intToLittleEndian(h4, out, outOff + 16);

        reset();

        return DIGEST_LENGTH;
    }

    public void reset()
    {
        super.reset();

        h0 = 0x67452301;
        h1 = 0xefcdab89;
        h2 = 0x98badcfe;
        h3 = 0x10325476;
        h4 = 0xc3d2e1f0;

        xOff = 0;
        for (int i = 0; i != x.length; i++)
        {
            x[i] = 0;
        }
    }

    protected void processBlock()
    {
        int[] h = { h0, h1, h2, h3, h4 };

        for (int round = 0; round < 4; ++round)
        {
            for (int i = 0; i < 4; ++i)
            {
                int[] w = XW[round][i];
                x[16 + i] = x[w[0]] ^ x[w[1]] ^ x[w[2]] ^ x[w[3]];
            }

            int[] l = L[round];
            int k = K[round];
            int s2 = S2[round];

            for (int j = 0; j < 20; ++j)
            {
                // the (A, B, C, D, E) roles rotate through h[] every step
                int a = (5 - (j % 5)) % 5;
                int b = (a + 1) % 5, c = (a + 2) % 5, d = (a + 3) % 5, e = (a + 4) % 5;

                int f;
                switch (round)
                {
                case 0:
                    f = (h[b] & h[c]) | (~h[b] & h[d]);
                    break;
                case 2:
                    f = h[c] ^ (h[b] | ~h[d]);
                    break;
                default:
                    f = h[b] ^ h[c] ^ h[d];
                    break;
                }

                h[e] += Integer.rotateLeft(h[a], S1[j]) + x[l[j]] + k + f;
                h[b] = Integer.rotateLeft(h[b], s2);
            }
        }

        h0 += h[0];
        h1 += h[1];
        h2 += h[2];
        h3 += h[3];
        h4 += h[4];

        xOff = 0;
        for (int i = 0; i < 16; i++)
        {
            x[i] = 0;
        }
    }

    public Memoable copy()
    {
        return new HAS160Digest(this);
    }

    public void reset(Memoable other)
    {
        copyState((HAS160Digest)other);
    }

    protected CryptoServiceProperties cryptoServiceProperties()
    {
        return new CryptoServiceProperties()
        {
            public int bitsOfSecurity()
            {
                return 80;
            }

            public String getServiceName()
            {
                return getAlgorithmName();
            }

            public CryptoServicePurpose getPurpose()
            {
                return purpose;
            }

            public Object getParams()
            {
                return null;
            }
        };
    }
}
