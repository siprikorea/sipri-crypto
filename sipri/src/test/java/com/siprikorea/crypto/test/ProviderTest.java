package com.siprikorea.crypto.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.siprikorea.crypto.digests.LSH256Digest;
import com.siprikorea.crypto.jcajce.provider.SipriCryptoProvider;
import com.siprikorea.crypto.signers.KCDSAUtil;
import com.siprikorea.crypto.signers.StandardKCDSAEncoding;
import junit.framework.TestCase;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * The SipriCrypto provider: every registered service resolves, and the JCA layer reproduces the
 * lightweight known answers.
 */
public class ProviderTest
    extends TestCase
{
    private static final String P = SipriCryptoProvider.PROVIDER_NAME;

    protected void setUp()
    {
        if (Security.getProvider(P) == null)
        {
            Security.addProvider(new SipriCryptoProvider());
        }
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testAllServicesResolve()
        throws Exception
    {
        int count = 0;
        for (java.util.Iterator it = Security.getProvider(P).getServices().iterator(); it.hasNext();)
        {
            java.security.Provider.Service s = (java.security.Provider.Service)it.next();
            assertNotNull(s.getType() + "." + s.getAlgorithm(), s.newInstance(null));
            count++;
        }
        assertEquals(26, count);
    }

    public void testDigests()
        throws Exception
    {
        assertEquals("307964ef34151d37c8047adec7ab50f4ff89762d",
            Hex.toHexString(MessageDigest.getInstance("HAS160", P).digest()));
        // LSH-256 of the empty message (lsh256.txt, size 0)
        assertEquals("f3cd416a03818217726cb47f4e4d2881c9c29fd445c18b66fb19dea1a81007c1",
            Hex.toHexString(MessageDigest.getInstance("LSH-256", P).digest()));

        String[] names = { "LSH-224", "LSH-256", "LSH-384", "LSH-512", "LSH-512-224", "LSH-512-256" };
        int[] lengths = { 28, 32, 48, 64, 28, 32 };
        for (int i = 0; i < names.length; i++)
        {
            MessageDigest md = MessageDigest.getInstance(names[i], P);
            assertEquals(names[i], lengths[i], md.getDigestLength());
            md.update(Strings.toByteArray("abc"));
            MessageDigest clone = (MessageDigest)md.clone();
            assertTrue(Arrays.areEqual(md.digest(), clone.digest()));
        }
    }

    public void testHmac()
        throws Exception
    {
        byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[] msg = Strings.toByteArray("HMAC-LSH");

        Mac mac = Mac.getInstance("HMAC-LSH256", P);
        mac.init(new SecretKeySpec(key, "HMACLSH256"));
        byte[] jca = mac.doFinal(msg);

        HMac lw = new HMac(new LSH256Digest());
        lw.init(new KeyParameter(key));
        lw.update(msg, 0, msg.length);
        byte[] expected = new byte[lw.getMacSize()];
        lw.doFinal(expected, 0);

        assertTrue(Arrays.areEqual(expected, jca));
    }

    public void testHIGHTCipher()
        throws Exception
    {
        List<Map<String, String>> groups = VectorFile.load("hight.txt");
        int n = 0;
        for (Map<String, String> g : groups)
        {
            SecretKey key = new SecretKeySpec(VectorFile.hex(g.get("Key")), "HIGHT");
            byte[] pt = VectorFile.hex(g.get("Plaintext"));
            byte[] ct = VectorFile.hex(g.get("Ciphertext"));
            Cipher c;
            if ("HIGHT/ECB".equals(g.get("Name")))
            {
                c = Cipher.getInstance("HIGHT/ECB/NoPadding", P);
                c.init(Cipher.ENCRYPT_MODE, key);
            }
            else
            {
                String mode = "HIGHT/CBC".equals(g.get("Name")) ? "CBC" : "CTR";
                c = Cipher.getInstance("HIGHT/" + mode + "/NoPadding", P);
                c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(VectorFile.hex(g.get("IV"))));
            }
            assertEquals(g.get("Name") + " " + g.get("Comment"), Hex.toHexString(ct), Hex.toHexString(c.doFinal(pt)));
            n++;
        }
        assertEquals(75, n);

        KeyGenerator kg = KeyGenerator.getInstance("HIGHT", P);
        SecretKey k = kg.generateKey();
        assertEquals(16, k.getEncoded().length);

        Cipher c = Cipher.getInstance("HIGHT/CBC/PKCS5Padding", P);
        c.init(Cipher.ENCRYPT_MODE, k);
        byte[] msg = Strings.toByteArray("Sipri Crypto HIGHT/CBC/PKCS5Padding round trip");
        byte[] enc = c.doFinal(msg);
        assertEquals(0, enc.length % 8);
        c.init(Cipher.DECRYPT_MODE, k, c.getParameters());
        assertTrue(Arrays.areEqual(msg, c.doFinal(enc)));

        Mac cmac = Mac.getInstance("HIGHT-CMAC", P);
        cmac.init(k);
        assertEquals(8, cmac.doFinal(msg).length);
    }

    public void testKCDSASampleThroughJCA()
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("KCDSA", P);
        String[] algs = { "SHA224withKCDSA", "SHA256withKCDSA", "SHA256withKCDSA", "SHA256withKCDSA", "HAS160withKCDSA" };
        List<Map<String, String>> groups = VectorFile.load("kcdsa_ttak.txt");

        for (int i = 0; i < groups.size(); i++)
        {
            Map<String, String> v = groups.get(i);
            BigInteger p = i(v, "P"), q = i(v, "Q"), g = i(v, "G");
            PublicKey pub = kf.generatePublic(new DSAPublicKeySpec(i(v, "Y"), p, q, g));
            PrivateKey priv = kf.generatePrivate(new DSAPrivateKeySpec(i(v, "X"), p, q, g));
            byte[] msg = VectorFile.hex(v.get("M"));

            // the standard's signature verifies through the JCA
            byte[] sample = StandardKCDSAEncoding.INSTANCE.encode(q, i(v, "R"), i(v, "S"));
            Signature verifier = Signature.getInstance(algs[i], P);
            verifier.initVerify(pub);
            verifier.update(msg);
            assertTrue(v.get("Sizes"), verifier.verify(sample));

            // and a fresh one round trips, also after re-encoding both keys
            Signature signer = Signature.getInstance(algs[i], P);
            signer.initSign(priv);
            signer.update(msg);
            byte[] sig = signer.sign();

            PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
            PrivateKey priv2 = kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
            assertEquals(pub, pub2);
            assertEquals(priv, priv2);
            assertEquals("KCDSA", pub2.getAlgorithm());

            verifier.initVerify(pub2);
            verifier.update(msg);
            assertTrue(verifier.verify(sig));

            checkMalformedSignatures(verifier, pub2, msg, sig);
        }
    }

    public void testKCDSAKeyPairGenerator()
        throws Exception
    {
        Map<String, String> v = VectorFile.load("kcdsa_ttak.txt").get(0);
        DSAParameterSpec spec = new DSAParameterSpec(i(v, "P"), i(v, "Q"), i(v, "G"));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("KCDSA", P);
        kpg.initialize(spec);
        KeyPair kp = kpg.generateKeyPair();
        roundTrip("SHA224withKCDSA", kp);

        // y = g^(x^-1), not DSA's g^x
        java.security.interfaces.DSAPrivateKey x = (java.security.interfaces.DSAPrivateKey)kp.getPrivate();
        assertEquals(KCDSAUtil.calculatePublicKey(new DSAParameters(spec.getP(), spec.getQ(), spec.getG()), x.getX()),
            ((DSAPublicKey)kp.getPublic()).getY());

        // legacy size generates its own TTAK parameters
        kpg.initialize(1024);
        roundTrip("HAS160withKCDSA", kpg.generateKeyPair());

        checkSerialization(kp);
    }

    public void testECKCDSASampleThroughJCA()
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance("ECKCDSA", P);
        for (Map<String, String> v : VectorFile.load("eckcdsa_ttak.txt"))
        {
            String curve = v.get("Curve");
            X9ECParameters x9 = ECNamedCurveTable.getByName(curve);
            ECParameterSpec spec = new ECNamedCurveSpec(curve, x9.getCurve(), x9.getG(), x9.getN(), x9.getH());

            PublicKey pub = kf.generatePublic(new ECPublicKeySpec(
                new java.security.spec.ECPoint(i(v, "Qx"), i(v, "Qy")), spec));
            PrivateKey priv = kf.generatePrivate(new ECPrivateKeySpec(i(v, "D"), spec));
            byte[] msg = VectorFile.hex(v.get("M"));
            String alg = v.get("Hash").equals("SHA-224") ? "SHA224withECKCDSA" : "SHA256withECKCDSA";

            byte[] sample = StandardKCDSAEncoding.INSTANCE.encode(x9.getN(), i(v, "R"), i(v, "S"));
            Signature verifier = Signature.getInstance(alg, P);
            verifier.initVerify(pub);
            verifier.update(msg);
            assertTrue(curve, verifier.verify(sample));

            PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
            PrivateKey priv2 = kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
            assertEquals(pub, pub2);
            assertEquals(priv, priv2);
            assertEquals("ECKCDSA", pub2.getAlgorithm());

            roundTrip(alg, new KeyPair(pub2, priv2));
            checkMalformedSignatures(verifier, pub2, msg, sample);
        }
    }

    public void testECKCDSAKeyPairGenerator()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC-KCDSA", P);
        KeyPair kp = kpg.generateKeyPair();
        assertEquals(256, ((ECPublicKey)kp.getPublic()).getParams().getOrder().bitLength());
        roundTrip("SHA256withECKCDSA", kp);

        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        kp = kpg.generateKeyPair();
        roundTrip("SHA384withECKCDSA", kp);
        roundTrip("SHA512withECKCDSA", kp);

        kpg.initialize(new ECGenParameterSpec("sect283k1"));
        roundTrip("SHA256withECKCDSA", kpg.generateKeyPair());

        checkSerialization(kp);

        // keys from another provider are accepted: an EC key pair whose public point is d^-1 G
        KeyPair bc = KeyPairGenerator.getInstance("EC", "BC").generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance("ECKCDSA", P);
        PrivateKey translated = (PrivateKey)kf.translateKey(bc.getPrivate());
        assertEquals("ECKCDSA", translated.getAlgorithm());
        assertEquals(((java.security.interfaces.ECPrivateKey)bc.getPrivate()).getS(),
            ((java.security.interfaces.ECPrivateKey)translated).getS());
    }

    public void testSetParameterIsChecked()
        throws Exception
    {
        String[] algs = { "SHA256withKCDSA", "SHA256withECKCDSA" };
        for (int i = 0; i < algs.length; i++)
        {
            try
            {
                Signature.getInstance(algs[i], P).setParameter(new ECGenParameterSpec("secp256r1"));
                fail("no exception");
            }
            catch (InvalidAlgorithmParameterException e)
            {
                // expected - never an unchecked exception
            }
        }
    }

    private static void roundTrip(String alg, KeyPair kp)
        throws Exception
    {
        byte[] msg = Strings.toByteArray("round trip " + alg);

        Signature s = Signature.getInstance(alg, P);
        s.initSign(kp.getPrivate());
        s.update(msg);
        byte[] sig = s.sign();

        s.initVerify(kp.getPublic());
        s.update(msg);
        assertTrue(alg, s.verify(sig));

        msg[0] ^= 1;
        s.update(msg);
        assertFalse(alg, s.verify(sig));
    }

    // per the provider convention: malformed input reports false, never throws unchecked
    private static void checkMalformedSignatures(Signature verifier, PublicKey pub, byte[] msg, byte[] sig)
        throws Exception
    {
        byte[][] bad = {
            new byte[0],
            new byte[3],
            new byte[sig.length],
            Arrays.append(sig, (byte)0),
            Arrays.copyOf(sig, sig.length - 1),
        };
        for (int i = 0; i < bad.length; i++)
        {
            verifier.initVerify(pub);
            verifier.update(msg);
            assertFalse("battery " + i, verifier.verify(bad[i]));
        }

        // the object is reusable after each failure
        verifier.update(msg);
        assertTrue(verifier.verify(sig));
    }

    private static void checkSerialization(KeyPair kp)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);
        oOut.writeObject(kp.getPublic());
        oOut.writeObject(kp.getPrivate());
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        assertEquals(kp.getPublic(), oIn.readObject());
        assertEquals(kp.getPrivate(), oIn.readObject());
    }

    private static BigInteger i(Map<String, String> v, String name)
    {
        return new BigInteger(1, VectorFile.hex(v.get(name)));
    }
}
