package com.siprikorea.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * KCDSA - the Korean Certificate-based Digital Signature Algorithm (TTAK.KO-12.0001/R4,
 * ISO/IEC 14888-3).
 * <p>
 * Unlike DSA the message is not hashed on its own: the hash input is {@code Z || M}, where
 * {@code Z = y mod 2^l} binds the signer's public key into the hash and {@code l} is the bit
 * length of the hash function's input block. The signer therefore consumes the whole message
 * through {@link #update(byte[], int, int)} rather than a pre-computed digest.
 * </p>
 * <p>
 * Keys are carried in the Bouncy Castle DSA parameter classes, since KCDSA shares DSA's
 * {@code (p, q, g)} domain. Note that the public key is {@code y = g^(x^-1 mod q) mod p}, not
 * DSA's {@code g^x mod p}; use {@link com.siprikorea.crypto.generators.KCDSAKeyPairGenerator}.
 * </p>
 * <p>
 * The standard parameter sets are (|p|, |q|, hash) = (2048, 224, SHA-224), (2048, 224, SHA-256),
 * (2048, 256, SHA-256) and (3072, 256, SHA-256); (1024, 160, HAS-160) remains for legacy
 * verification. Any digest whose output is at least |q| bits long is accepted.
 * </p>
 */
public class KCDSASigner
    implements Signer
{
    private final ExtendedDigest digest;
    private final DSAKCalculator kCalculator;
    private final KCDSAEncoding encoding;

    private boolean forSigning;
    private DSAKeyParameters key;
    private BigInteger y;
    private byte[] z;
    private SecureRandom random;

    /**
     * Construct a signer using random k values and the DER {@code SEQUENCE { r INTEGER, s INTEGER }}
     * signature encoding.
     *
     * @param digest the hash function, e.g. SHA-224 or SHA-256.
     */
    public KCDSASigner(ExtendedDigest digest)
    {
        this(digest, new RandomDSAKCalculator(), StandardKCDSAEncoding.INSTANCE);
    }

    /**
     * Construct a signer with an explicit k calculator and signature encoding.
     *
     * @param digest      the hash function.
     * @param kCalculator source of the per-signature secret k.
     * @param encoding    signature encoding.
     */
    public KCDSASigner(ExtendedDigest digest, DSAKCalculator kCalculator, KCDSAEncoding encoding)
    {
        this.digest = digest;
        this.kCalculator = kCalculator;
        this.encoding = encoding;
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        SecureRandom providedRandom = null;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom rParam = (ParametersWithRandom)param;

            providedRandom = rParam.getRandom();
            param = rParam.getParameters();
        }

        if (forSigning)
        {
            if (!(param instanceof DSAPrivateKeyParameters))
            {
                throw new IllegalArgumentException("KCDSA signing requires a DSAPrivateKeyParameters key");
            }

            DSAPrivateKeyParameters priv = (DSAPrivateKeyParameters)param;
            DSAParameters params = priv.getParameters();
            checkDomain(params);

            this.y = KCDSAUtil.calculatePublicKey(params, priv.getX());
            this.random = kCalculator.isDeterministic() ? null : CryptoServicesRegistrar.getSecureRandom(providedRandom);
            this.key = priv;
        }
        else
        {
            if (!(param instanceof DSAPublicKeyParameters))
            {
                throw new IllegalArgumentException("KCDSA verification requires a DSAPublicKeyParameters key");
            }

            DSAPublicKeyParameters pub = (DSAPublicKeyParameters)param;
            checkDomain(pub.getParameters());

            this.y = pub.getY();
            this.random = null;
            this.key = pub;
        }

        this.forSigning = forSigning;
        this.z = KCDSAUtil.rightmostBytes(y, digest.getByteLength());

        reset();
    }

    private void checkDomain(DSAParameters params)
    {
        if (params == null)
        {
            throw new IllegalArgumentException("KCDSA key has no domain parameters");
        }
        if (digest.getDigestSize() * 8 < params.getQ().bitLength())
        {
            throw new IllegalArgumentException("digest " + digest.getAlgorithmName()
                + " is shorter than q (" + params.getQ().bitLength() + " bits)");
        }
    }

    public void update(byte b)
    {
        digest.update(b);
    }

    public void update(byte[] in, int off, int len)
    {
        digest.update(in, off, len);
    }

    public byte[] generateSignature()
    {
        BigInteger[] rs = generateSignatureComponents();

        return encoding.encode(key.getParameters().getQ(), rs[0], rs[1]);
    }

    /**
     * Complete the signature over the message passed in so far.
     *
     * @return {r, s}, where r is the beta-bit hash value as a non-negative integer.
     */
    public BigInteger[] generateSignatureComponents()
    {
        if (!forSigning)
        {
            throw new IllegalStateException("KCDSASigner not initialised for signature generation");
        }

        DSAParameters params = key.getParameters();
        BigInteger p = params.getP(), q = params.getQ(), g = params.getG();
        BigInteger x = ((DSAPrivateKeyParameters)key).getX();
        int beta = q.bitLength();

        // step 5: H = trunc(Hash(Z || M), beta)
        BigInteger h = hashTruncated(beta);

        kCalculator.init(q, random);

        try
        {
            for (;;)
            {
                BigInteger k = kCalculator.nextK();

                // steps 2-3: W = g^k mod p, R = trunc(Hash(W), beta)
                BigInteger w = g.modPow(k, p);
                BigInteger r = hashOf(BigIntegers.asUnsignedByteArray(KCDSAUtil.byteLength(p), w), beta);

                // steps 6-7: E = (R xor H) mod q, S = x(k - E) mod q
                BigInteger e = r.xor(h).mod(q);
                BigInteger s = x.multiply(k.subtract(e)).mod(q);

                if (s.signum() != 0)
                {
                    return new BigInteger[]{ r, s };
                }
            }
        }
        finally
        {
            reset();
        }
    }

    public boolean verifySignature(byte[] signature)
    {
        BigInteger[] rs;
        try
        {
            rs = encoding.decode(key.getParameters().getQ(), signature);
        }
        catch (Exception e)
        {
            reset();
            return false;
        }

        return verifySignatureComponents(rs[0], rs[1]);
    }

    /**
     * Verify {r, s} against the message passed in so far.
     *
     * @param r the beta-bit hash value as a non-negative integer.
     * @param s the signature value.
     * @return true if the signature verifies.
     */
    public boolean verifySignatureComponents(BigInteger r, BigInteger s)
    {
        if (forSigning)
        {
            throw new IllegalStateException("KCDSASigner not initialised for verification");
        }

        DSAParameters params = key.getParameters();
        BigInteger p = params.getP(), q = params.getQ(), g = params.getG();
        int beta = q.bitLength();

        try
        {
            // step 3: H' = trunc(Hash(Z || M'), beta) - always consume the message, then check ranges
            BigInteger h = hashTruncated(beta);

            // step 1: R' must fit in beta bits, 0 < S' < q
            if (r.signum() < 0 || r.bitLength() > beta || s.signum() <= 0 || s.compareTo(q) >= 0)
            {
                return false;
            }

            // steps 4-6: E' = (R' xor H') mod q, W' = y^S' g^E' mod p, trunc(Hash(W'), beta) == R'
            BigInteger e = r.xor(h).mod(q);
            BigInteger w = y.modPow(s, p).multiply(g.modPow(e, p)).mod(p);
            BigInteger v = hashOf(BigIntegers.asUnsignedByteArray(KCDSAUtil.byteLength(p), w), beta);

            return v.equals(r);
        }
        finally
        {
            reset();
        }
    }

    public void reset()
    {
        digest.reset();
        if (z != null)
        {
            digest.update(z, 0, z.length);
        }
    }

    private BigInteger hashTruncated(int bits)
    {
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);

        BigInteger v = KCDSAUtil.truncateRight(out, bits);
        Arrays.fill(out, (byte)0);
        return v;
    }

    private BigInteger hashOf(byte[] data, int bits)
    {
        digest.reset();
        digest.update(data, 0, data.length);
        return hashTruncated(bits);
    }
}
