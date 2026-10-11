package com.siprikorea.crypto.jcajce.provider.kcdsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import com.siprikorea.crypto.digests.HAS160Digest;
import com.siprikorea.crypto.signers.KCDSASigner;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;

/**
 * KCDSA Signature services. Any {@link java.security.interfaces.DSAPrivateKey} /
 * {@link java.security.interfaces.DSAPublicKey} is accepted; signatures are DER
 * {@code SEQUENCE { r INTEGER, s INTEGER }}.
 */
public class SignatureSpi
    extends java.security.SignatureSpi
{
    private final KCDSASigner signer;

    protected SignatureSpi(ExtendedDigest digest)
    {
        this.signer = new KCDSASigner(digest);
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        CipherParameters param = DSAUtil.generatePublicKeyParameter(publicKey);
        try
        {
            signer.init(false, param);
        }
        catch (IllegalArgumentException e)
        {
            throw SecurityExceptions.invalidKeyException(e.getMessage(), e);
        }
    }

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        engineInitSign(privateKey, null);
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException
    {
        CipherParameters param = DSAUtil.generatePrivateKeyParameter(privateKey);
        if (random != null)
        {
            param = new ParametersWithRandom(param, random);
        }
        try
        {
            signer.init(true, param);
        }
        catch (IllegalArgumentException e)
        {
            throw SecurityExceptions.invalidKeyException(e.getMessage(), e);
        }
    }

    protected void engineUpdate(byte b)
    {
        signer.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len)
    {
        signer.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            return signer.generateSignature();
        }
        catch (Exception e)
        {
            throw SecurityExceptions.signatureException(e.toString(), e);
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
    {
        return signer.verifySignature(sigBytes);
    }

    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("KCDSA signatures take no parameters");
    }

    /**
     * @deprecated replaced with {@link #engineSetParameter(AlgorithmParameterSpec)}
     */
    protected void engineSetParameter(String param, Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated no replacement
     */
    protected Object engineGetParameter(String param)
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    public static class SHA224
        extends SignatureSpi
    {
        public SHA224()
        {
            super(new SHA224Digest());
        }
    }

    public static class SHA256
        extends SignatureSpi
    {
        public SHA256()
        {
            super(new SHA256Digest());
        }
    }

    /**
     * Legacy HAS160withKCDSA, for verifying and interoperating with existing signatures.
     */
    public static class HAS160
        extends SignatureSpi
    {
        public HAS160()
        {
            super(new HAS160Digest());
        }
    }
}
