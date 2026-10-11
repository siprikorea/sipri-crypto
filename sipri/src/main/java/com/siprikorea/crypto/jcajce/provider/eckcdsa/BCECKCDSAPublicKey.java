package com.siprikorea.crypto.jcajce.provider.eckcdsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import com.siprikorea.crypto.asn1.SipriObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.util.Exceptions;

/**
 * An EC-KCDSA public key {@code Q = d^-1 G}, encoded with the ISO/IEC 14888-3 EC-KCDSA OID
 * {@code 1.0.14888.3.0.5} and X9.62 curve parameters.
 */
public class BCECKCDSAPublicKey
    implements ECPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient ECKCDSADomain domain;
    private transient ECPublicKeyParameters params;

    BCECKCDSAPublicKey(ECKCDSADomain domain, org.bouncycastle.math.ec.ECPoint q)
    {
        this.domain = domain;
        this.params = new ECPublicKeyParameters(q, domain.domain);
    }

    BCECKCDSAPublicKey(SubjectPublicKeyInfo info)
        throws IOException
    {
        init(info);
    }

    private void init(SubjectPublicKeyInfo info)
        throws IOException
    {
        try
        {
            this.domain = ECKCDSADomain.fromAsn1(X962Parameters.getInstance(info.getAlgorithm().getParameters()));
        }
        catch (java.security.InvalidAlgorithmParameterException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }

        byte[] encoding = info.getPublicKeyData().getOctets();
        this.params = new ECPublicKeyParameters(domain.domain.getCurve().decodePoint(encoding), domain.domain);
    }

    ECPublicKeyParameters engineGetKeyParameters()
    {
        return params;
    }

    public String getAlgorithm()
    {
        return "ECKCDSA";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        return KeyUtil.getEncodedSubjectPublicKeyInfo(
            new AlgorithmIdentifier(SipriObjectIdentifiers.ecKcdsa, domain.asn1),
            params.getQ().getEncoded(false));
    }

    public ECParameterSpec getParams()
    {
        return domain.spec;
    }

    public ECPoint getW()
    {
        return EC5Util.convertPoint(params.getQ());
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof ECPublicKey))
        {
            return false;
        }

        ECPublicKey other = (ECPublicKey)o;
        return getW().equals(other.getW())
            && domain.spec.getOrder().equals(other.getParams().getOrder())
            && domain.spec.getGenerator().equals(other.getParams().getGenerator());
    }

    public int hashCode()
    {
        return getW().hashCode() ^ domain.spec.getOrder().hashCode();
    }

    public String toString()
    {
        return "EC-KCDSA Public Key [" + domain.spec.getOrder().bitLength() + "]";
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        init(SubjectPublicKeyInfo.getInstance((byte[])in.readObject()));
    }

    private void writeObject(ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();
        out.writeObject(getEncoded());
    }
}
