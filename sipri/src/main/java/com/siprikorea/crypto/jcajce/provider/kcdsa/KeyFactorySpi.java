package com.siprikorea.crypto.jcajce.provider.kcdsa;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.siprikorea.crypto.asn1.SipriObjectIdentifiers;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;

/**
 * KCDSA KeyFactory: X.509 / PKCS#8 encodings (ISO/IEC 14888-3 OID, or the Korean e-Government
 * OID on input) and {@link DSAPublicKeySpec} / {@link DSAPrivateKeySpec}.
 */
public class KeyFactorySpi
    extends java.security.KeyFactorySpi
{
    static boolean isKcdsaOid(ASN1ObjectIdentifier oid)
    {
        return SipriObjectIdentifiers.kcdsa.equals(oid) || SipriObjectIdentifiers.kcdsa_kisa.equals(oid);
    }

    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            try
            {
                SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(((X509EncodedKeySpec)keySpec).getEncoded());
                if (!isKcdsaOid(info.getAlgorithm().getAlgorithm()))
                {
                    throw new InvalidKeySpecException("not a KCDSA public key: " + info.getAlgorithm().getAlgorithm());
                }
                return new BCKCDSAPublicKey(info);
            }
            catch (InvalidKeySpecException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw SecurityExceptions.invalidKeySpecException("unable to decode KCDSA public key: " + e.getMessage(), e);
            }
        }
        if (keySpec instanceof DSAPublicKeySpec)
        {
            DSAPublicKeySpec s = (DSAPublicKeySpec)keySpec;
            return new BCKCDSAPublicKey(new DSAPublicKeyParameters(s.getY(), new DSAParameters(s.getP(), s.getQ(), s.getG())));
        }

        throw new InvalidKeySpecException("unsupported key spec for KCDSA public key: "
            + (keySpec == null ? "null" : keySpec.getClass().getName()));
    }

    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof PKCS8EncodedKeySpec)
        {
            try
            {
                PrivateKeyInfo info = PrivateKeyInfo.getInstance(((PKCS8EncodedKeySpec)keySpec).getEncoded());
                if (!isKcdsaOid(info.getPrivateKeyAlgorithm().getAlgorithm()))
                {
                    throw new InvalidKeySpecException("not a KCDSA private key: " + info.getPrivateKeyAlgorithm().getAlgorithm());
                }
                return new BCKCDSAPrivateKey(info);
            }
            catch (InvalidKeySpecException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw SecurityExceptions.invalidKeySpecException("unable to decode KCDSA private key: " + e.getMessage(), e);
            }
        }
        if (keySpec instanceof DSAPrivateKeySpec)
        {
            DSAPrivateKeySpec s = (DSAPrivateKeySpec)keySpec;
            return new BCKCDSAPrivateKey(new DSAPrivateKeyParameters(s.getX(), new DSAParameters(s.getP(), s.getQ(), s.getG())));
        }

        throw new InvalidKeySpecException("unsupported key spec for KCDSA private key: "
            + (keySpec == null ? "null" : keySpec.getClass().getName()));
    }

    protected KeySpec engineGetKeySpec(Key key, Class spec)
        throws InvalidKeySpecException
    {
        if (spec == null)
        {
            throw new InvalidKeySpecException("null spec class");
        }
        if (key instanceof DSAPublicKey)
        {
            DSAPublicKey k = (DSAPublicKey)key;
            if (spec.isAssignableFrom(DSAPublicKeySpec.class))
            {
                return new DSAPublicKeySpec(k.getY(), k.getParams().getP(), k.getParams().getQ(), k.getParams().getG());
            }
            if (spec.isAssignableFrom(X509EncodedKeySpec.class))
            {
                return new X509EncodedKeySpec(toKcdsaPublic(k).getEncoded());
            }
        }
        else if (key instanceof DSAPrivateKey)
        {
            DSAPrivateKey k = (DSAPrivateKey)key;
            if (spec.isAssignableFrom(DSAPrivateKeySpec.class))
            {
                return new DSAPrivateKeySpec(k.getX(), k.getParams().getP(), k.getParams().getQ(), k.getParams().getG());
            }
            if (spec.isAssignableFrom(PKCS8EncodedKeySpec.class))
            {
                return new PKCS8EncodedKeySpec(toKcdsaPrivate(k).getEncoded());
            }
        }

        throw new InvalidKeySpecException("unsupported key/spec combination: "
            + (key == null ? "null" : key.getClass().getName()) + " / " + spec.getName());
    }

    protected Key engineTranslateKey(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCKCDSAPublicKey || key instanceof BCKCDSAPrivateKey)
        {
            return key;
        }
        if (key instanceof DSAPublicKey)
        {
            return toKcdsaPublic((DSAPublicKey)key);
        }
        if (key instanceof DSAPrivateKey)
        {
            return toKcdsaPrivate((DSAPrivateKey)key);
        }

        throw new InvalidKeyException("key type unknown to the KCDSA KeyFactory: "
            + (key == null ? "null" : key.getClass().getName()));
    }

    private static BCKCDSAPublicKey toKcdsaPublic(DSAPublicKey k)
    {
        if (k instanceof BCKCDSAPublicKey)
        {
            return (BCKCDSAPublicKey)k;
        }
        return new BCKCDSAPublicKey(new DSAPublicKeyParameters(k.getY(),
            new DSAParameters(k.getParams().getP(), k.getParams().getQ(), k.getParams().getG())));
    }

    private static BCKCDSAPrivateKey toKcdsaPrivate(DSAPrivateKey k)
    {
        if (k instanceof BCKCDSAPrivateKey)
        {
            return (BCKCDSAPrivateKey)k;
        }
        return new BCKCDSAPrivateKey(new DSAPrivateKeyParameters(k.getX(),
            new DSAParameters(k.getParams().getP(), k.getParams().getQ(), k.getParams().getG())));
    }
}
