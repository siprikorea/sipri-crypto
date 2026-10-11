package com.siprikorea.crypto.jcajce.provider.digest;

import com.siprikorea.crypto.digests.HAS160Digest;
import org.bouncycastle.jcajce.provider.digest.BCMessageDigest;

/**
 * JCA MessageDigest service for the legacy HAS-160 hash.
 */
public final class HAS160
{
    private HAS160()
    {
    }

    public static class Digest
        extends BCMessageDigest
        implements Cloneable
    {
        public Digest()
        {
            super(new HAS160Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Digest d = (Digest)super.clone();
            d.digest = new HAS160Digest((HAS160Digest)digest);
            return d;
        }
    }
}
