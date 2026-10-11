package com.siprikorea.crypto.jcajce.provider.eckcdsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.siprikorea.crypto.asn1.SipriObjectIdentifiers;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;

/**
 * EC-KCDSA KeyFactory: X.509 / PKCS#8 encodings (ISO/IEC 14888-3 OID, or the Korean e-Government
 * OID on input) and {@link ECPublicKeySpec} / {@link ECPrivateKeySpec}.
 */
public class KeyFactorySpi
    extends java.security.KeyFactorySpi
{
    static boolean isEcKcdsaOid(ASN1ObjectIdentifier oid)
    {
        return SipriObjectIdentifiers.ecKcdsa.equals(oid) || SipriObjectIdentifiers.ecKcdsa_kisa.equals(oid);
    }

    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        try
        {
            if (keySpec instanceof X509EncodedKeySpec)
            {
                SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(((X509EncodedKeySpec)keySpec).getEncoded());
                if (!isEcKcdsaOid(info.getAlgorithm().getAlgorithm()))
                {
                    throw new InvalidKeySpecException("not an EC-KCDSA public key: " + info.getAlgorithm().getAlgorithm());
                }
                return new BCECKCDSAPublicKey(info);
            }
            if (keySpec instanceof ECPublicKeySpec)
            {
                ECPublicKeySpec s = (ECPublicKeySpec)keySpec;
                ECKCDSADomain domain = ECKCDSADomain.fromSpec(s.getParams());
                return new BCECKCDSAPublicKey(domain, EC5Util.convertPoint(domain.domain.getCurve(), s.getW()));
            }
        }
        catch (InvalidKeySpecException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw SecurityExceptions.invalidKeySpecException("unable to decode EC-KCDSA public key: " + e.getMessage(), e);
        }

        throw new InvalidKeySpecException("unsupported key spec for EC-KCDSA public key: "
            + (keySpec == null ? "null" : keySpec.getClass().getName()));
    }

    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        try
        {
            if (keySpec instanceof PKCS8EncodedKeySpec)
            {
                PrivateKeyInfo info = PrivateKeyInfo.getInstance(((PKCS8EncodedKeySpec)keySpec).getEncoded());
                if (!isEcKcdsaOid(info.getPrivateKeyAlgorithm().getAlgorithm()))
                {
                    throw new InvalidKeySpecException("not an EC-KCDSA private key: " + info.getPrivateKeyAlgorithm().getAlgorithm());
                }
                return new BCECKCDSAPrivateKey(info);
            }
            if (keySpec instanceof ECPrivateKeySpec)
            {
                ECPrivateKeySpec s = (ECPrivateKeySpec)keySpec;
                return new BCECKCDSAPrivateKey(ECKCDSADomain.fromSpec(s.getParams()), s.getS());
            }
        }
        catch (InvalidKeySpecException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw SecurityExceptions.invalidKeySpecException("unable to decode EC-KCDSA private key: " + e.getMessage(), e);
        }

        throw new InvalidKeySpecException("unsupported key spec for EC-KCDSA private key: "
            + (keySpec == null ? "null" : keySpec.getClass().getName()));
    }

    protected KeySpec engineGetKeySpec(Key key, Class spec)
        throws InvalidKeySpecException
    {
        if (spec == null)
        {
            throw new InvalidKeySpecException("null spec class");
        }
        try
        {
            if (key instanceof ECPublicKey)
            {
                ECPublicKey k = (ECPublicKey)key;
                if (spec.isAssignableFrom(ECPublicKeySpec.class))
                {
                    return new ECPublicKeySpec(k.getW(), k.getParams());
                }
                if (spec.isAssignableFrom(X509EncodedKeySpec.class))
                {
                    return new X509EncodedKeySpec(engineTranslateKey(k).getEncoded());
                }
            }
            else if (key instanceof ECPrivateKey)
            {
                ECPrivateKey k = (ECPrivateKey)key;
                if (spec.isAssignableFrom(ECPrivateKeySpec.class))
                {
                    return new ECPrivateKeySpec(k.getS(), k.getParams());
                }
                if (spec.isAssignableFrom(PKCS8EncodedKeySpec.class))
                {
                    return new PKCS8EncodedKeySpec(engineTranslateKey(k).getEncoded());
                }
            }
        }
        catch (InvalidKeyException e)
        {
            throw SecurityExceptions.invalidKeySpecException(e.getMessage(), e);
        }

        throw new InvalidKeySpecException("unsupported key/spec combination: "
            + (key == null ? "null" : key.getClass().getName()) + " / " + spec.getName());
    }

    protected Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCECKCDSAPublicKey || key instanceof BCECKCDSAPrivateKey)
        {
            return key;
        }

        try
        {
            if (key instanceof ECPublicKey)
            {
                ECPublicKey k = (ECPublicKey)key;
                ECKCDSADomain domain = ECKCDSADomain.fromSpec(k.getParams());
                return new BCECKCDSAPublicKey(domain, EC5Util.convertPoint(domain.domain.getCurve(), k.getW()));
            }
            if (key instanceof ECPrivateKey)
            {
                ECPrivateKey k = (ECPrivateKey)key;
                return new BCECKCDSAPrivateKey(ECKCDSADomain.fromSpec(k.getParams()), k.getS());
            }
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw SecurityExceptions.invalidKeyException(e.getMessage(), e);
        }

        throw new InvalidKeyException("key type unknown to the EC-KCDSA KeyFactory: "
            + (key == null ? "null" : key.getClass().getName()));
    }
}
