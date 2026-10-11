package com.siprikorea.crypto.signers;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Encoding of a KCDSA or EC-KCDSA signature value {r, s}.
 * <p>
 * Unlike DSA, r is a hash value rather than a residue mod q (or n), so implementations must not
 * range-check r against the group order.
 * </p>
 */
public interface KCDSAEncoding
{
    /**
     * Decode a signature.
     *
     * @param n        the group order (q for KCDSA, n for EC-KCDSA).
     * @param encoding the encoded signature.
     * @return {r, s}.
     * @throws IOException if the encoding is malformed.
     */
    BigInteger[] decode(BigInteger n, byte[] encoding)
        throws IOException;

    /**
     * Encode a signature.
     *
     * @param n the group order (q for KCDSA, n for EC-KCDSA).
     * @param r the hash value r.
     * @param s the signature value s.
     * @return the encoded signature.
     */
    byte[] encode(BigInteger n, BigInteger r, BigInteger s);
}
