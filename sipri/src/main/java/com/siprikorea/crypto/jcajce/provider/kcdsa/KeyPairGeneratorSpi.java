package com.siprikorea.crypto.jcajce.provider.kcdsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;

import com.siprikorea.crypto.digests.HAS160Digest;
import com.siprikorea.crypto.generators.KCDSAKeyPairGenerator;
import com.siprikorea.crypto.generators.KCDSAParametersGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;

/**
 * KCDSA KeyPairGenerator.
 * <p>
 * Initialise with a {@link DSAParameterSpec} holding existing domain parameters (recommended), or
 * with a size of 2048 (|q| = 224), 3072 (|q| = 256) or the legacy 1024 (|q| = 160) to generate
 * fresh domain parameters by the TTAK.KO-12.0001 procedure first - which can take a while.
 * Without initialisation 2048-bit parameters are generated.
 * </p>
 */
public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private int strength = 2048;
    private SecureRandom random;
    private DSAParameters params;

    public KeyPairGeneratorSpi()
    {
        super("KCDSA");
    }

    public void initialize(int strength, SecureRandom random)
    {
        if (strength != 1024 && strength != 2048 && strength != 3072)
        {
            throw new InvalidParameterException("KCDSA strength must be 2048, 3072 or (legacy) 1024");
        }

        this.strength = strength;
        this.random = random;
        this.params = null;
    }

    public void initialize(AlgorithmParameterSpec spec, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (!(spec instanceof DSAParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("KCDSA key generation requires a DSAParameterSpec");
        }

        DSAParameterSpec s = (DSAParameterSpec)spec;
        this.params = new DSAParameters(s.getP(), s.getQ(), s.getG());
        this.random = random;
    }

    public KeyPair generateKeyPair()
    {
        SecureRandom rand = CryptoServicesRegistrar.getSecureRandom(random);

        if (params == null)
        {
            Digest digest;
            int beta;
            switch (strength)
            {
            case 1024:
                digest = new HAS160Digest();
                beta = 160;
                break;
            case 3072:
                digest = new SHA256Digest();
                beta = 256;
                break;
            default:
                digest = new SHA224Digest();
                beta = 224;
                break;
            }

            KCDSAParametersGenerator pGen = new KCDSAParametersGenerator(digest);
            pGen.init(strength, beta, rand);
            params = pGen.generateParameters();
        }

        KCDSAKeyPairGenerator gen = new KCDSAKeyPairGenerator();
        gen.init(new DSAKeyGenerationParameters(rand, params));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        return new KeyPair(new BCKCDSAPublicKey((DSAPublicKeyParameters)kp.getPublic()),
            new BCKCDSAPrivateKey((DSAPrivateKeyParameters)kp.getPrivate()));
    }
}
