package com.siprikorea.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import com.siprikorea.crypto.digests.HAS160Digest;
import com.siprikorea.crypto.generators.KCDSAKeyPairGenerator;
import com.siprikorea.crypto.generators.KCDSAParametersGenerator;
import com.siprikorea.crypto.signers.KCDSASigner;
import com.siprikorea.crypto.signers.KCDSAUtil;
import com.siprikorea.crypto.signers.StandardKCDSAEncoding;
import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.BigIntegers;

/**
 * KCDSA against the five sample computations of TTAK.KO-12.0001/R4 Appendix II: parameter
 * generation (J, p, q from the seed and count), the public key, and the signature for a fixed k.
 */
public class KCDSATest
    extends TestCase
{
    public void testSampleSignatures()
        throws Exception
    {
        List<Map<String, String>> groups = VectorFile.load("kcdsa_ttak.txt");
        assertEquals(5, groups.size());

        for (Map<String, String> v : groups)
        {
            String label = v.get("Sizes");
            DSAParameters params = new DSAParameters(i(v, "P"), i(v, "Q"), i(v, "G"));
            BigInteger x = i(v, "X");

            // y = g^(x^-1) mod p and Z = y mod 2^l
            BigInteger y = KCDSAUtil.calculatePublicKey(params, x);
            assertEquals(label, i(v, "Y"), y);
            assertEquals(label, i(v, "Z"), y.mod(BigInteger.ONE.shiftLeft(512)));

            byte[] msg = VectorFile.hex(v.get("M"));

            KCDSASigner signer = new KCDSASigner(digest(label), new FixedKCalculator(i(v, "KKEY")),
                StandardKCDSAEncoding.INSTANCE);
            signer.init(true, new DSAPrivateKeyParameters(x, params));
            signer.update(msg, 0, msg.length);
            BigInteger[] rs = signer.generateSignatureComponents();
            assertEquals(label + " R", i(v, "R"), rs[0]);
            assertEquals(label + " S", i(v, "S"), rs[1]);

            KCDSASigner verifier = new KCDSASigner(digest(label));
            verifier.init(false, new DSAPublicKeyParameters(y, params));
            verifier.update(msg, 0, msg.length);
            assertTrue(label, verifier.verifySignatureComponents(rs[0], rs[1]));

            // the verifier is reusable and rejects a different message / signature
            verifier.update(msg, 0, msg.length - 1);
            assertFalse(label, verifier.verifySignatureComponents(rs[0], rs[1]));
            verifier.update(msg, 0, msg.length);
            assertFalse(label, verifier.verifySignatureComponents(rs[0], rs[1].add(BigInteger.ONE)));
            verifier.update(msg, 0, msg.length);
            assertFalse(label, verifier.verifySignatureComponents(rs[0].setBit(params.getQ().bitLength()), rs[1]));
            verifier.update(msg, 0, msg.length);
            assertTrue(label, verifier.verifySignatureComponents(rs[0], rs[1]));
        }
    }

    public void testParameterGeneration()
        throws Exception
    {
        for (Map<String, String> v : VectorFile.load("kcdsa_ttak.txt"))
        {
            String label = v.get("Sizes");
            String[] sizes = label.split(",");
            int alpha = Integer.parseInt(sizes[0]);
            int beta = Integer.parseInt(sizes[1]);
            byte[] seed = VectorFile.hex(v.get("Seedb"));

            BigInteger j = KCDSAParametersGenerator.generateJ(digest(label), seed, alpha, beta);
            assertEquals(label + " J", i(v, "J"), j);

            int count = Integer.parseInt(v.get("Count"));
            BigInteger[] pq = KCDSAParametersGenerator.generatePQ(digest(label), seed, j, count, alpha, beta);
            assertNotNull(label, pq);
            assertEquals(label + " P", i(v, "P"), pq[0]);
            assertEquals(label + " Q", i(v, "Q"), pq[1]);

            // g = h^(2J) mod p with the sample h
            BigInteger h = new BigInteger(1, VectorFile.hex(v.get("H")));
            assertEquals(label + " G", i(v, "G"), h.modPow(j.shiftLeft(1), pq[0]));
        }
    }

    public void testParameterSearchFindsFirstCount()
        throws Exception
    {
        // the full count search for the legacy (1024, 160) sample: no earlier count may succeed
        Map<String, String> v = VectorFile.load("kcdsa_ttak.txt").get(4);
        assertEquals("1024,160,HAS-160", v.get("Sizes"));
        byte[] seed = VectorFile.hex(v.get("Seedb"));
        BigInteger j = i(v, "J");
        int expected = Integer.parseInt(v.get("Count"));

        for (int count = 1; count < expected; count++)
        {
            assertNull(KCDSAParametersGenerator.generatePQ(new HAS160Digest(), seed, j, count, 1024, 160));
        }
        assertNotNull(KCDSAParametersGenerator.generatePQ(new HAS160Digest(), seed, j, expected, 1024, 160));
    }

    public void testGeneratedKeys()
    {
        SecureRandom random = new SecureRandom();

        KCDSAParametersGenerator pGen = new KCDSAParametersGenerator(new HAS160Digest());
        pGen.init(1024, 160, random);
        DSAParameters params = pGen.generateParameters();
        assertEquals(1024, params.getP().bitLength());
        assertEquals(160, params.getQ().bitLength());
        assertEquals(BigInteger.ONE, params.getG().modPow(params.getQ(), params.getP()));

        // the recorded seed and counter regenerate p and q
        byte[] seed = params.getValidationParameters().getSeed();
        BigInteger j = KCDSAParametersGenerator.generateJ(new HAS160Digest(), seed, 1024, 160);
        BigInteger[] pq = KCDSAParametersGenerator.generatePQ(new HAS160Digest(), seed, j,
            params.getValidationParameters().getCounter(), 1024, 160);
        assertEquals(params.getP(), pq[0]);
        assertEquals(params.getQ(), pq[1]);

        KCDSAKeyPairGenerator kpGen = new KCDSAKeyPairGenerator();
        kpGen.init(new DSAKeyGenerationParameters(random, params));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        byte[] msg = BigIntegers.asUnsignedByteArray(BigInteger.valueOf(0x12345678L));
        KCDSASigner signer = new KCDSASigner(new SHA256Digest());
        signer.init(true, new ParametersWithRandom(kp.getPrivate(), random));
        signer.update(msg, 0, msg.length);
        byte[] sig = signer.generateSignature();

        KCDSASigner verifier = new KCDSASigner(new SHA256Digest());
        verifier.init(false, kp.getPublic());
        verifier.update(msg, 0, msg.length);
        assertTrue(verifier.verifySignature(sig));

        verifier.update(msg, 0, msg.length);
        sig[sig.length - 1] ^= 1;
        assertFalse(verifier.verifySignature(sig));

        verifier.update(msg, 0, msg.length);
        assertFalse(verifier.verifySignature(new byte[]{ 0x30, 0x00 }));
    }

    public void testDigestShorterThanQRejected()
    {
        DSAParameters params = new DSAParameters(BigInteger.valueOf(23), BigInteger.ONE.shiftLeft(255).add(BigInteger.ONE),
            BigInteger.valueOf(2));
        try
        {
            new KCDSASigner(new SHA224Digest()).init(false, new DSAPublicKeyParameters(BigInteger.valueOf(4), params));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertTrue(e.getMessage().startsWith("digest SHA-224 is shorter than q"));
        }
    }

    private static ExtendedDigest digest(String sizes)
    {
        if (sizes.endsWith("SHA-224"))
        {
            return new SHA224Digest();
        }
        if (sizes.endsWith("SHA-256"))
        {
            return new SHA256Digest();
        }
        return new HAS160Digest();
    }

    private static BigInteger i(Map<String, String> v, String name)
    {
        return new BigInteger(1, VectorFile.hex(v.get(name)));
    }
}
