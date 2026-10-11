package com.siprikorea.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.signers.DSAKCalculator;

/**
 * Returns a fixed k, so signatures can be compared with the standards' sample values.
 */
class FixedKCalculator
    implements DSAKCalculator
{
    private final BigInteger k;

    FixedKCalculator(BigInteger k)
    {
        this.k = k;
    }

    public boolean isDeterministic()
    {
        return true;
    }

    public void init(BigInteger n, SecureRandom random)
    {
    }

    public void init(BigInteger n, BigInteger d, byte[] message)
    {
    }

    public BigInteger nextK()
    {
        return k;
    }
}
