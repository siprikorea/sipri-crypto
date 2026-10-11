package com.siprikorea.crypto.jcajce.provider.eckcdsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

import com.siprikorea.crypto.asn1.SipriObjectIdentifiers;
import com.siprikorea.crypto.signers.ECKCDSASigner;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.util.Exceptions;

/**
 * An EC-KCDSA private key d, encoded as PKCS#8 wrapping an RFC 5915 ECPrivateKey under the
 * ISO/IEC 14888-3 EC-KCDSA OID. The embedded public key is {@code Q = d^-1 G}.
 */
public class BCECKCDSAPrivateKey
    implements ECPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient ECKCDSADomain domain;
    private transient ECPrivateKeyParameters params;

    BCECKCDSAPrivateKey(ECKCDSADomain domain, BigInteger d)
    {
        this.domain = domain;
        this.params = new ECPrivateKeyParameters(d, domain.domain);
    }

    BCECKCDSAPrivateKey(PrivateKeyInfo info)
        throws IOException
    {
        init(info);
    }

    private void init(PrivateKeyInfo info)
        throws IOException
    {
        try
        {
            this.domain = ECKCDSADomain.fromAsn1(X962Parameters.getInstance(info.getPrivateKeyAlgorithm().getParameters()));
        }
        catch (java.security.InvalidAlgorithmParameterException e)
        {
            throw Exceptions.ioException(e.getMessage(), e);
        }

        org.bouncycastle.asn1.sec.ECPrivateKey ec = org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(info.parsePrivateKey());
        this.params = new ECPrivateKeyParameters(ec.getKey(), domain.domain);
    }

    ECPrivateKeyParameters engineGetKeyParameters()
    {
        return params;
    }

    public String getAlgorithm()
    {
        return "ECKCDSA";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        int orderBits = domain.domain.getN().bitLength();
        DERBitString pub = new DERBitString(
            ECKCDSASigner.calculatePublicKey(domain.domain, params.getD()).getEncoded(false));

        return KeyUtil.getEncodedPrivateKeyInfo(
            new AlgorithmIdentifier(SipriObjectIdentifiers.ecKcdsa, domain.asn1),
            new org.bouncycastle.asn1.sec.ECPrivateKey(orderBits, params.getD(), pub, null));
    }

    public ECParameterSpec getParams()
    {
        return domain.spec;
    }

    public BigInteger getS()
    {
        return params.getD();
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof ECPrivateKey))
        {
            return false;
        }

        ECPrivateKey other = (ECPrivateKey)o;
        return getS().equals(other.getS())
            && domain.spec.getOrder().equals(other.getParams().getOrder())
            && domain.spec.getGenerator().equals(other.getParams().getGenerator());
    }

    public int hashCode()
    {
        return getS().hashCode() ^ domain.spec.getOrder().hashCode();
    }

    public String toString()
    {
        return "EC-KCDSA Private Key [" + domain.spec.getOrder().bitLength() + "]";
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        init(PrivateKeyInfo.getInstance((byte[])in.readObject()));
    }

    private void writeObject(ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();
        out.writeObject(getEncoded());
    }
}
