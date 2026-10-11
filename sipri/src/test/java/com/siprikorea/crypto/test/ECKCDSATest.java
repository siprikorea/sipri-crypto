package com.siprikorea.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import com.siprikorea.crypto.generators.ECKCDSAKeyPairGenerator;
import com.siprikorea.crypto.signers.ECKCDSASigner;
import com.siprikorea.crypto.signers.StandardKCDSAEncoding;
import junit.framework.TestCase;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;

/**
 * EC-KCDSA against the nine sample computations of TTAK.KO-12.0015/R3 Appendix II (prime and
 * binary curves, SHA-224 and SHA-256).
 */
public class ECKCDSATest
    extends TestCase
{
    public void testSampleSignatures()
        throws Exception
    {
        List<Map<String, String>> groups = VectorFile.load("eckcdsa_ttak.txt");
        assertEquals(9, groups.size());

        for (Map<String, String> v : groups)
        {
            String label = v.get("Curve") + "/" + v.get("Hash");
            X9ECParameters x9 = ECNamedCurveTable.getByName(v.get("Curve"));
            ECDomainParameters domain = new ECDomainParameters(x9);
            BigInteger d = i(v, "D");

            ECPoint q = ECKCDSASigner.calculatePublicKey(domain, d);
            assertEquals(label + " Qx", i(v, "Qx"), q.getAffineXCoord().toBigInteger());
            assertEquals(label + " Qy", i(v, "Qy"), q.getAffineYCoord().toBigInteger());

            byte[] msg = VectorFile.hex(v.get("M"));

            ECKCDSASigner signer = new ECKCDSASigner(digest(v.get("Hash")), new FixedKCalculator(i(v, "K")),
                StandardKCDSAEncoding.INSTANCE);
            signer.init(true, new ECPrivateKeyParameters(d, domain));
            signer.update(msg, 0, msg.length);
            BigInteger[] rs = signer.generateSignatureComponents();
            assertEquals(label + " R", i(v, "R"), rs[0]);
            assertEquals(label + " S", i(v, "S"), rs[1]);

            ECKCDSASigner verifier = new ECKCDSASigner(digest(v.get("Hash")));
            verifier.init(false, new ECPublicKeyParameters(q, domain));
            verifier.update(msg, 0, msg.length);
            assertTrue(label, verifier.verifySignatureComponents(rs[0], rs[1]));

            verifier.update(msg, 1, msg.length - 1);
            assertFalse(label, verifier.verifySignatureComponents(rs[0], rs[1]));
            verifier.update(msg, 0, msg.length);
            assertFalse(label, verifier.verifySignatureComponents(rs[0], domain.getN().subtract(rs[1])));
            verifier.update(msg, 0, msg.length);
            assertFalse(label, verifier.verifySignatureComponents(rs[0], domain.getN()));
            verifier.update(msg, 0, msg.length);
            assertTrue(label, verifier.verifySignatureComponents(rs[0], rs[1]));
        }
    }

    public void testGeneratedKeys()
    {
        SecureRandom random = new SecureRandom();
        String[] curves = { "secp256r1", "secp384r1", "sect283k1" };

        for (int c = 0; c < curves.length; c++)
        {
            ECDomainParameters domain = new ECDomainParameters(ECNamedCurveTable.getByName(curves[c]));
            ECKCDSAKeyPairGenerator gen = new ECKCDSAKeyPairGenerator();
            gen.init(new ECKeyGenerationParameters(domain, random));
            AsymmetricCipherKeyPair kp = gen.generateKeyPair();

            // SHA-512 output exceeds w for every curve here, exercising the mod 2^(8w) reduction
            ExtendedDigest[] digests = { new SHA256Digest(), new SHA512Digest() };
            for (int i = 0; i < digests.length; i++)
            {
                byte[] msg = Strings.toByteArray("EC-KCDSA round trip " + curves[c]);

                ECKCDSASigner signer = new ECKCDSASigner(digests[i]);
                signer.init(true, kp.getPrivate());
                signer.update(msg, 0, msg.length);
                byte[] sig = signer.generateSignature();

                ECKCDSASigner verifier = new ECKCDSASigner(digests[i]);
                verifier.init(false, kp.getPublic());
                verifier.update(msg, 0, msg.length);
                assertTrue(curves[c], verifier.verifySignature(sig));

                sig[sig.length - 1] ^= 0x01;
                verifier.update(msg, 0, msg.length);
                assertFalse(curves[c], verifier.verifySignature(sig));
            }
        }
    }

    private static ExtendedDigest digest(String name)
    {
        return name.equals("SHA-224") ? (ExtendedDigest)new SHA224Digest() : new SHA256Digest();
    }

    private static BigInteger i(Map<String, String> v, String name)
    {
        return new BigInteger(1, VectorFile.hex(v.get(name)));
    }
}
