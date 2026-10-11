package com.siprikorea.crypto.jcajce.provider.eckcdsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

import com.siprikorea.crypto.generators.ECKCDSAKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * EC-KCDSA KeyPairGenerator. Initialise with an {@link ECGenParameterSpec} naming a curve, an
 * {@link ECParameterSpec}, or a size (224, 256, 384, 521 select the corresponding NIST prime
 * curve). The default is secp256r1.
 */
public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private ECKCDSADomain domain;
    private SecureRandom random;

    public KeyPairGeneratorSpi()
    {
        super("ECKCDSA");
    }

    public void initialize(int strength, SecureRandom random)
    {
        String name;
        switch (strength)
        {
        case 224:
            name = "secp224r1";
            break;
        case 256:
            name = "secp256r1";
            break;
        case 384:
            name = "secp384r1";
            break;
        case 521:
            name = "secp521r1";
            break;
        default:
            throw new InvalidParameterException("unknown EC-KCDSA key size: " + strength);
        }

        try
        {
            this.domain = ECKCDSADomain.fromName(name);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new InvalidParameterException(e.getMessage());
        }
        this.random = random;
    }

    public void initialize(AlgorithmParameterSpec spec, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (spec instanceof ECGenParameterSpec)
        {
            this.domain = ECKCDSADomain.fromName(((ECGenParameterSpec)spec).getName());
        }
        else if (spec instanceof ECParameterSpec)
        {
            this.domain = ECKCDSADomain.fromSpec((ECParameterSpec)spec);
        }
        else
        {
            throw new InvalidAlgorithmParameterException("EC-KCDSA key generation requires an ECGenParameterSpec or ECParameterSpec");
        }
        this.random = random;
    }

    public KeyPair generateKeyPair()
    {
        if (domain == null)
        {
            initialize(256, null);
        }

        ECKCDSAKeyPairGenerator gen = new ECKCDSAKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(domain.domain, CryptoServicesRegistrar.getSecureRandom(random)));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        return new KeyPair(new BCECKCDSAPublicKey(domain, ((ECPublicKeyParameters)kp.getPublic()).getQ()),
            new BCECKCDSAPrivateKey(domain, ((ECPrivateKeyParameters)kp.getPrivate()).getD()));
    }
}
