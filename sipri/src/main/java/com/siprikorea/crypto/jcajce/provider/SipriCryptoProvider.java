package com.siprikorea.crypto.jcajce.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

import com.siprikorea.crypto.asn1.SipriObjectIdentifiers;

/**
 * The Sipri Crypto JCA/JCE provider ("SipriCrypto"): Korean national algorithms that the Bouncy
 * Castle provider does not carry.
 * <ul>
 * <li>Signature: SHA224withKCDSA, SHA256withKCDSA, HAS160withKCDSA (legacy);
 * SHA224withECKCDSA, SHA256withECKCDSA, SHA384withECKCDSA, SHA512withECKCDSA</li>
 * <li>KeyPairGenerator / KeyFactory: KCDSA, ECKCDSA</li>
 * <li>MessageDigest: LSH-224, LSH-256, LSH-384, LSH-512, LSH-512-224, LSH-512-256, HAS-160</li>
 * <li>Mac: HmacLSH224, HmacLSH256, HmacLSH384, HmacLSH512, HIGHT-CMAC</li>
 * <li>Cipher / KeyGenerator / AlgorithmParameters: HIGHT</li>
 * </ul>
 * SEED, ARIA and LEA are already provided by {@code BouncyCastleProvider} ("BC"); install both
 * providers to cover the full Korean algorithm set.
 * <pre>
 * Security.addProvider(new BouncyCastleProvider());
 * Security.addProvider(new SipriCryptoProvider());
 * Signature sig = Signature.getInstance("SHA256withECKCDSA", "SipriCrypto");
 * </pre>
 */
public final class SipriCryptoProvider
    extends Provider
{
    private static final long serialVersionUID = 1L;

    public static final String PROVIDER_NAME = "SipriCrypto";

    private static final String INFO = "Sipri Crypto Provider v1.0 (KCDSA, EC-KCDSA, LSH, HIGHT, HAS-160; built on Bouncy Castle)";

    private static final String PKG = "com.siprikorea.crypto.jcajce.provider";

    public SipriCryptoProvider()
    {
        super(PROVIDER_NAME, 1.0, INFO);

        AccessController.doPrivileged(new PrivilegedAction()
        {
            public Object run()
            {
                setup();
                return null;
            }
        });
    }

    private void setup()
    {
        // digests
        String lsh = PKG + ".digest.LSH$";
        add("MessageDigest.LSH-224", lsh + "Digest224");
        add("MessageDigest.LSH-256", lsh + "Digest256");
        add("MessageDigest.LSH-384", lsh + "Digest384");
        add("MessageDigest.LSH-512", lsh + "Digest512");
        add("MessageDigest.LSH-512-224", lsh + "Digest512_224");
        add("MessageDigest.LSH-512-256", lsh + "Digest512_256");
        alias("MessageDigest", "LSH224", "LSH-224");
        alias("MessageDigest", "LSH256", "LSH-256");
        alias("MessageDigest", "LSH384", "LSH-384");
        alias("MessageDigest", "LSH512", "LSH-512");
        alias("MessageDigest", "LSH512-224", "LSH-512-224");
        alias("MessageDigest", "LSH512-256", "LSH-512-256");

        add("MessageDigest.HAS-160", PKG + ".digest.HAS160$Digest");
        alias("MessageDigest", "HAS160", "HAS-160");

        add("Mac.HMACLSH224", lsh + "HashMac224");
        add("Mac.HMACLSH256", lsh + "HashMac256");
        add("Mac.HMACLSH384", lsh + "HashMac384");
        add("Mac.HMACLSH512", lsh + "HashMac512");
        alias("Mac", "HMAC-LSH224", "HMACLSH224");
        alias("Mac", "HMAC-LSH256", "HMACLSH256");
        alias("Mac", "HMAC-LSH384", "HMACLSH384");
        alias("Mac", "HMAC-LSH512", "HMACLSH512");

        // HIGHT
        String hight = PKG + ".symmetric.HIGHT$";
        add("Cipher.HIGHT", hight + "ECB");
        add("Cipher.HIGHT SupportedKeyFormats", "RAW");
        add("KeyGenerator.HIGHT", hight + "KeyGen");
        add("AlgorithmParameters.HIGHT", hight + "AlgParams");
        add("Mac.HIGHT-CMAC", hight + "Mac");
        alias("Mac", "HIGHTCMAC", "HIGHT-CMAC");

        // KCDSA
        String kcdsa = PKG + ".kcdsa.";
        add("KeyPairGenerator.KCDSA", kcdsa + "KeyPairGeneratorSpi");
        add("KeyFactory.KCDSA", kcdsa + "KeyFactorySpi");
        alias("KeyFactory", SipriObjectIdentifiers.kcdsa.getId(), "KCDSA");
        alias("KeyFactory", SipriObjectIdentifiers.kcdsa_kisa.getId(), "KCDSA");
        alias("KeyPairGenerator", SipriObjectIdentifiers.kcdsa.getId(), "KCDSA");

        add("Signature.SHA224WITHKCDSA", kcdsa + "SignatureSpi$SHA224");
        add("Signature.SHA256WITHKCDSA", kcdsa + "SignatureSpi$SHA256");
        add("Signature.HAS160WITHKCDSA", kcdsa + "SignatureSpi$HAS160");
        signatureKeyClasses("SHA224WITHKCDSA", "java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey");
        signatureKeyClasses("SHA256WITHKCDSA", "java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey");
        signatureKeyClasses("HAS160WITHKCDSA", "java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey");

        // EC-KCDSA
        String eckcdsa = PKG + ".eckcdsa.";
        add("KeyPairGenerator.ECKCDSA", eckcdsa + "KeyPairGeneratorSpi");
        add("KeyFactory.ECKCDSA", eckcdsa + "KeyFactorySpi");
        alias("KeyPairGenerator", "EC-KCDSA", "ECKCDSA");
        alias("KeyFactory", "EC-KCDSA", "ECKCDSA");
        alias("KeyFactory", SipriObjectIdentifiers.ecKcdsa.getId(), "ECKCDSA");
        alias("KeyFactory", SipriObjectIdentifiers.ecKcdsa_kisa.getId(), "ECKCDSA");
        alias("KeyPairGenerator", SipriObjectIdentifiers.ecKcdsa.getId(), "ECKCDSA");

        String[] sha = { "SHA224", "SHA256", "SHA384", "SHA512" };
        for (int i = 0; i != sha.length; i++)
        {
            String name = sha[i] + "WITHECKCDSA";
            add("Signature." + name, eckcdsa + "SignatureSpi$" + sha[i]);
            alias("Signature", sha[i] + "WITHEC-KCDSA", name);
            signatureKeyClasses(name, "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        }
    }

    private void add(String key, String value)
    {
        if (containsKey(key))
        {
            throw new IllegalStateException("duplicate provider key (" + key + ") found");
        }
        put(key, value);
    }

    private void alias(String type, String alias, String target)
    {
        add("Alg.Alias." + type + "." + alias, target);
    }

    private void signatureKeyClasses(String name, String classes)
    {
        add("Signature." + name + " SupportedKeyClasses", classes);
    }
}
