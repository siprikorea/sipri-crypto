package com.siprikorea.crypto.jcajce.provider.eckcdsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import com.siprikorea.crypto.signers.ECKCDSASigner;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;

/**
 * EC-KCDSA Signature services. Any {@link java.security.interfaces.ECPrivateKey} /
 * {@link java.security.interfaces.ECPublicKey} is accepted; signatures are DER
 * {@code SEQUENCE { r INTEGER, s INTEGER }}.
 */
public class SignatureSpi
    extends java.security.SignatureSpi
{
    private final ECKCDSASigner signer;

    protected SignatureSpi(ExtendedDigest digest)
    {
        this.signer = new ECKCDSASigner(digest);
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        CipherParameters param = ECUtil.generatePublicKeyParameter(publicKey);
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
        CipherParameters param = ECUtil.generatePrivateKeyParameter(privateKey);
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
        throw new InvalidAlgorithmParameterException("EC-KCDSA signatures take no parameters");
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

    public static class SHA384
        extends SignatureSpi
    {
        public SHA384()
        {
            super(new SHA384Digest());
        }
    }

    public static class SHA512
        extends SignatureSpi
    {
        public SHA512()
        {
            super(new SHA512Digest());
        }
    }
}
