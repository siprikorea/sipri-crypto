package com.siprikorea.crypto.jcajce.provider.kcdsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;

import com.siprikorea.crypto.asn1.SipriObjectIdentifiers;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;

/**
 * A KCDSA public key {@code y = g^(x^-1) mod p}. It implements {@link DSAPublicKey} because KCDSA
 * shares DSA's domain, but its algorithm is "KCDSA" and it encodes with the ISO/IEC 14888-3 KCDSA
 * OID {@code 1.0.14888.3.0.2}.
 */
public class BCKCDSAPublicKey
    implements DSAPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient DSAPublicKeyParameters params;
    private transient DSAParams dsaSpec;

    BCKCDSAPublicKey(DSAPublicKeyParameters params)
    {
        init(params);
    }

    BCKCDSAPublicKey(SubjectPublicKeyInfo info)
        throws IOException
    {
        DSAParameter p = DSAParameter.getInstance(info.getAlgorithm().getParameters());
        BigInteger y = ASN1Integer.getInstance(info.parsePublicKey()).getValue();

        init(new DSAPublicKeyParameters(y, new DSAParameters(p.getP(), p.getQ(), p.getG())));
    }

    private void init(DSAPublicKeyParameters params)
    {
        DSAParameters d = params.getParameters();

        this.params = params;
        this.dsaSpec = new DSAParameterSpec(d.getP(), d.getQ(), d.getG());
    }

    DSAPublicKeyParameters engineGetKeyParameters()
    {
        return params;
    }

    public String getAlgorithm()
    {
        return "KCDSA";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        return KeyUtil.getEncodedSubjectPublicKeyInfo(
            new AlgorithmIdentifier(SipriObjectIdentifiers.kcdsa,
                new DSAParameter(dsaSpec.getP(), dsaSpec.getQ(), dsaSpec.getG()).toASN1Primitive()),
            new ASN1Integer(getY()));
    }

    public DSAParams getParams()
    {
        return dsaSpec;
    }

    public BigInteger getY()
    {
        return params.getY();
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof DSAPublicKey))
        {
            return false;
        }

        DSAPublicKey other = (DSAPublicKey)o;
        return getY().equals(other.getY())
            && dsaSpec.getG().equals(other.getParams().getG())
            && dsaSpec.getP().equals(other.getParams().getP())
            && dsaSpec.getQ().equals(other.getParams().getQ());
    }

    public int hashCode()
    {
        return getY().hashCode() ^ dsaSpec.getG().hashCode() ^ dsaSpec.getP().hashCode() ^ dsaSpec.getQ().hashCode();
    }

    public String toString()
    {
        return "KCDSA Public Key [" + dsaSpec.getP().bitLength() + "/" + dsaSpec.getQ().bitLength() + "]";
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        init(new BCKCDSAPublicKey(SubjectPublicKeyInfo.getInstance((byte[])in.readObject())).params);
    }

    private void writeObject(ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();
        out.writeObject(getEncoded());
    }
}
