package com.siprikorea.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;

/**
 * EC-KCDSA - the elliptic curve variant of KCDSA (TTAK.KO-12.0015/R3, ISO/IEC 14888-3).
 * <p>
 * The public key is {@code Q = d^-1 G}. The message hash input is {@code cQ || M}, where
 * {@code cQ = MSB(xQ || yQ, L)} is the first L bytes (the hash input block length) of the public
 * key coordinates, zero-padded on the right when the coordinates are shorter. When the hash output
 * is longer than {@code w = ceil(log256 n)} bytes, hash values are reduced to their rightmost w
 * bytes, as the standard specifies.
 * </p>
 */
public class ECKCDSASigner
    implements Signer
{
    private final ExtendedDigest digest;
    private final DSAKCalculator kCalculator;
    private final KCDSAEncoding encoding;

    private boolean forSigning;
    private ECKeyParameters key;
    private ECPoint q;
    private byte[] cQ;
    private SecureRandom random;

    /**
     * Construct a signer using random k values and the DER {@code SEQUENCE { r INTEGER, s INTEGER }}
     * signature encoding.
     *
     * @param digest the hash function, e.g. SHA-224 or SHA-256.
     */
    public ECKCDSASigner(ExtendedDigest digest)
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
    public ECKCDSASigner(ExtendedDigest digest, DSAKCalculator kCalculator, KCDSAEncoding encoding)
    {
        this.digest = digest;
        this.kCalculator = kCalculator;
        this.encoding = encoding;
    }

    /**
     * Compute the EC-KCDSA public key point {@code Q = d^-1 G}.
     *
     * @param domain the curve domain parameters.
     * @param d      the private key, 0 &lt; d &lt; n.
     * @return the normalized public point.
     */
    public static ECPoint calculatePublicKey(ECDomainParameters domain, BigInteger d)
    {
        BigInteger n = domain.getN();
        if (d.signum() <= 0 || d.compareTo(n) >= 0)
        {
            throw new IllegalArgumentException("EC-KCDSA private key out of range");
        }

        BigInteger dInv = org.bouncycastle.util.BigIntegers.modOddInverse(n, d);
        return new FixedPointCombMultiplier().multiply(domain.getG(), dInv).normalize();
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
            if (!(param instanceof ECPrivateKeyParameters))
            {
                throw new IllegalArgumentException("EC-KCDSA signing requires an ECPrivateKeyParameters key");
            }

            ECPrivateKeyParameters priv = (ECPrivateKeyParameters)param;

            this.q = calculatePublicKey(priv.getParameters(), priv.getD());
            this.random = kCalculator.isDeterministic() ? null : CryptoServicesRegistrar.getSecureRandom(providedRandom);
            this.key = priv;
        }
        else
        {
            if (!(param instanceof ECPublicKeyParameters))
            {
                throw new IllegalArgumentException("EC-KCDSA verification requires an ECPublicKeyParameters key");
            }

            ECPublicKeyParameters pub = (ECPublicKeyParameters)param;

            this.q = pub.getQ().normalize();
            this.random = null;
            this.key = pub;
        }

        this.forSigning = forSigning;

        // cQ = MSB(xQ || yQ, L)
        byte[] x = q.getAffineXCoord().getEncoded();
        byte[] y = q.getAffineYCoord().getEncoded();
        byte[] xy = Arrays.concatenate(x, y);
        int l = digest.getByteLength();
        this.cQ = new byte[l];
        System.arraycopy(xy, 0, cQ, 0, Math.min(l, xy.length));

        reset();
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

        return encoding.encode(key.getParameters().getN(), rs[0], rs[1]);
    }

    /**
     * Complete the signature over the message passed in so far.
     *
     * @return {r, s}, where r is the (possibly reduced) hash value as a non-negative integer.
     */
    public BigInteger[] generateSignatureComponents()
    {
        if (!forSigning)
        {
            throw new IllegalStateException("ECKCDSASigner not initialised for signature generation");
        }

        ECDomainParameters ec = key.getParameters();
        BigInteger n = ec.getN();
        BigInteger d = ((ECPrivateKeyParameters)key).getD();

        // step 5: v = Hash(cQ || M)
        BigInteger v = hashReduced(n);

        kCalculator.init(n, random);

        FixedPointCombMultiplier basePointMultiplier = new FixedPointCombMultiplier();
        try
        {
            for (;;)
            {
                BigInteger k = kCalculator.nextK();

                // steps 2-3: (x1, y1) = kG, r = Hash(x1)
                ECPoint kG = basePointMultiplier.multiply(ec.getG(), k).normalize();
                BigInteger r = hashOf(kG.getAffineXCoord().getEncoded(), n);

                // steps 6-7: e = (r xor v) mod n, t = d(k - e) mod n
                BigInteger e = r.xor(v).mod(n);
                BigInteger t = d.multiply(k.subtract(e)).mod(n);

                if (t.signum() != 0)
                {
                    return new BigInteger[]{ r, t };
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
            rs = encoding.decode(key.getParameters().getN(), signature);
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
     * @param r the (possibly reduced) hash value as a non-negative integer.
     * @param s the signature value.
     * @return true if the signature verifies.
     */
    public boolean verifySignatureComponents(BigInteger r, BigInteger s)
    {
        if (forSigning)
        {
            throw new IllegalStateException("ECKCDSASigner not initialised for verification");
        }

        ECDomainParameters ec = key.getParameters();
        BigInteger n = ec.getN();

        try
        {
            // step 3: v' = Hash(cQ || M')
            BigInteger v = hashReduced(n);

            // step 1: |r'| no longer than the (reduced) hash, 0 < s' < n
            if (r.signum() < 0 || r.bitLength() > hashBytes(n) * 8 || s.signum() <= 0 || s.compareTo(n) >= 0)
            {
                return false;
            }

            // steps 4-6: e' = (r' xor v') mod n, (x2, y2) = s'Q + e'G, Hash(x2) == r'
            BigInteger e = r.xor(v).mod(n);
            ECPoint point = ECAlgorithms.sumOfTwoMultiplies(q, s, ec.getG(), e).normalize();
            if (point.isInfinity())
            {
                return false;
            }

            return hashOf(point.getAffineXCoord().getEncoded(), n).equals(r);
        }
        finally
        {
            reset();
        }
    }

    public void reset()
    {
        digest.reset();
        if (cQ != null)
        {
            digest.update(cQ, 0, cQ.length);
        }
    }

    // the hash value length in bytes after the "mod 2^(8w)" reduction
    private int hashBytes(BigInteger n)
    {
        return Math.min(digest.getDigestSize(), (n.bitLength() + 7) / 8);
    }

    private BigInteger hashReduced(BigInteger n)
    {
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);

        BigInteger v = KCDSAUtil.truncateRight(out, hashBytes(n) * 8);
        Arrays.fill(out, (byte)0);
        return v;
    }

    private BigInteger hashOf(byte[] data, BigInteger n)
    {
        digest.reset();
        digest.update(data, 0, data.length);
        return hashReduced(n);
    }
}
