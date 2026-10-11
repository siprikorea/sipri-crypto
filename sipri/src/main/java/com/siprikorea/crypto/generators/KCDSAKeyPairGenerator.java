package com.siprikorea.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.siprikorea.crypto.signers.KCDSAUtil;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.util.BigIntegers;

/**
 * KCDSA key pair generator: a uniformly random private key 0 &lt; x &lt; q and the public key
 * {@code y = g^(x^-1 mod q) mod p}.
 */
public class KCDSAKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private DSAKeyGenerationParameters param;

    public void init(KeyGenerationParameters param)
    {
        this.param = (DSAKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        DSAParameters params = param.getParameters();
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom(param.getRandom());

        BigInteger x = BigIntegers.createRandomInRange(BigInteger.ONE, params.getQ().subtract(BigInteger.ONE), random);
        BigInteger y = KCDSAUtil.calculatePublicKey(params, x);

        return new AsymmetricCipherKeyPair(new DSAPublicKeyParameters(y, params), new DSAPrivateKeyParameters(x, params));
    }
}
