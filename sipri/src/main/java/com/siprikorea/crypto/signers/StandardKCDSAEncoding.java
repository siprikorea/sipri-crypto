package com.siprikorea.crypto.signers;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 * DER encoding {@code SEQUENCE { r INTEGER, s INTEGER }} of a KCDSA / EC-KCDSA signature, the same
 * shape as an ECDSA/DSA signature value. Decoding is strict: the input must be the DER encoding
 * that would be produced for the decoded values.
 */
public class StandardKCDSAEncoding
    implements KCDSAEncoding
{
    public static final StandardKCDSAEncoding INSTANCE = new StandardKCDSAEncoding();

    public BigInteger[] decode(BigInteger n, byte[] encoding)
        throws IOException
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoding));
        if (seq.size() == 2)
        {
            BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
            BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();

            if (r.signum() >= 0 && s.signum() >= 0 && Arrays.areEqual(encoding, encode(n, r, s)))
            {
                return new BigInteger[]{ r, s };
            }
        }

        throw new IllegalArgumentException("malformed KCDSA signature");
    }

    public byte[] encode(BigInteger n, BigInteger r, BigInteger s)
    {
        try
        {
            return new DERSequence(new ASN1Integer[]{ new ASN1Integer(r), new ASN1Integer(s) })
                .getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to encode KCDSA signature: " + e.getMessage());
        }
    }
}
