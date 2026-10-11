package com.siprikorea.crypto.jcajce.provider.kcdsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAParameterSpec;

import com.siprikorea.crypto.asn1.SipriObjectIdentifiers;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;

/**
 * A KCDSA private key x, encoded as PKCS#8 with the ISO/IEC 14888-3 KCDSA OID.
 */
public class BCKCDSAPrivateKey
    implements DSAPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient DSAPrivateKeyParameters params;
    private transient DSAParams dsaSpec;

    BCKCDSAPrivateKey(DSAPrivateKeyParameters params)
    {
        init(params);
    }

    BCKCDSAPrivateKey(PrivateKeyInfo info)
        throws IOException
    {
        DSAParameter p = DSAParameter.getInstance(info.getPrivateKeyAlgorithm().getParameters());
        BigInteger x = ASN1Integer.getInstance(info.parsePrivateKey()).getValue();

        init(new DSAPrivateKeyParameters(x, new DSAParameters(p.getP(), p.getQ(), p.getG())));
    }

    private void init(DSAPrivateKeyParameters params)
    {
        DSAParameters d = params.getParameters();

        this.params = params;
        this.dsaSpec = new DSAParameterSpec(d.getP(), d.getQ(), d.getG());
    }

    DSAPrivateKeyParameters engineGetKeyParameters()
    {
        return params;
    }

    public String getAlgorithm()
    {
        return "KCDSA";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        return KeyUtil.getEncodedPrivateKeyInfo(
            new AlgorithmIdentifier(SipriObjectIdentifiers.kcdsa,
                new DSAParameter(dsaSpec.getP(), dsaSpec.getQ(), dsaSpec.getG()).toASN1Primitive()),
            new ASN1Integer(getX()));
    }

    public DSAParams getParams()
    {
        return dsaSpec;
    }

    public BigInteger getX()
    {
        return params.getX();
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof DSAPrivateKey))
        {
            return false;
        }

        DSAPrivateKey other = (DSAPrivateKey)o;
        return getX().equals(other.getX())
            && dsaSpec.getG().equals(other.getParams().getG())
            && dsaSpec.getP().equals(other.getParams().getP())
            && dsaSpec.getQ().equals(other.getParams().getQ());
    }

    public int hashCode()
    {
        return getX().hashCode() ^ dsaSpec.getG().hashCode() ^ dsaSpec.getP().hashCode() ^ dsaSpec.getQ().hashCode();
    }

    public String toString()
    {
        return "KCDSA Private Key [" + dsaSpec.getP().bitLength() + "/" + dsaSpec.getQ().bitLength() + "]";
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        init(new BCKCDSAPrivateKey(PrivateKeyInfo.getInstance((byte[])in.readObject())).params);
    }

    private void writeObject(ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();
        out.writeObject(getEncoded());
    }
}
