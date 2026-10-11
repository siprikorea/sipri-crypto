package com.siprikorea.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.siprikorea.crypto.signers.ECKCDSASigner;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.BigIntegers;

/**
 * EC-KCDSA key pair generator: a uniformly random private key 0 &lt; d &lt; n and the public key
 * {@code Q = d^-1 G} (note: not ECDSA's {@code dG}).
 */
public class ECKCDSAKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private ECKeyGenerationParameters param;

    public void init(KeyGenerationParameters param)
    {
        this.param = (ECKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        ECDomainParameters domain = param.getDomainParameters();
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom(param.getRandom());

        BigInteger d = BigIntegers.createRandomInRange(BigInteger.ONE, domain.getN().subtract(BigInteger.ONE), random);

        return new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(ECKCDSASigner.calculatePublicKey(domain, d), domain),
            new ECPrivateKeyParameters(d, domain));
    }
}
