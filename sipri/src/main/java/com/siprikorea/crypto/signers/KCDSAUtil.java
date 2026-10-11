package com.siprikorea.crypto.signers;

import java.math.BigInteger;

import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.util.BigIntegers;

/**
 * Helpers shared by the KCDSA and EC-KCDSA implementations.
 */
public final class KCDSAUtil
{
    private KCDSAUtil()
    {
    }

    /**
     * Compute the KCDSA public key {@code y = g^(x^-1 mod q) mod p}.
     *
     * @param params the domain parameters.
     * @param x      the private key, 0 &lt; x &lt; q.
     * @return the public key y.
     */
    public static BigInteger calculatePublicKey(DSAParameters params, BigInteger x)
    {
        BigInteger q = params.getQ();
        if (x.signum() <= 0 || x.compareTo(q) >= 0)
        {
            throw new IllegalArgumentException("KCDSA private key out of range");
        }

        return params.getG().modPow(BigIntegers.modOddInverse(q, x), params.getP());
    }

    static int byteLength(BigInteger v)
    {
        return (v.bitLength() + 7) / 8;
    }

    /**
     * The rightmost {@code len} bytes of the big-endian encoding of v, left-padded with zeros when
     * v is shorter, i.e. I2OSP(v mod 256^len, len).
     */
    static byte[] rightmostBytes(BigInteger v, int len)
    {
        byte[] full = BigIntegers.asUnsignedByteArray(Math.max(byteLength(v), len), v);
        byte[] out = new byte[len];
        System.arraycopy(full, full.length - len, out, 0, len);
        return out;
    }

    /**
     * The integer value of the rightmost {@code bits} bits of {@code data}.
     */
    static BigInteger truncateRight(byte[] data, int bits)
    {
        BigInteger v = new BigInteger(1, data);
        if (data.length * 8 > bits)
        {
            v = v.mod(BigInteger.ONE.shiftLeft(bits));
        }
        return v;
    }
}
