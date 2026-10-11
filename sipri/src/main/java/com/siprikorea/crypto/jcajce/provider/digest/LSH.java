package com.siprikorea.crypto.jcajce.provider.digest;

import com.siprikorea.crypto.digests.LSH256Digest;
import com.siprikorea.crypto.digests.LSH512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jcajce.provider.digest.BCMessageDigest;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

/**
 * JCA MessageDigest and HMAC services for the LSH family (KS X 3262).
 */
public final class LSH
{
    private LSH()
    {
    }

    public static class Digest256
        extends BCMessageDigest
        implements Cloneable
    {
        public Digest256()
        {
            this(256);
        }

        Digest256(int bits)
        {
            super(new LSH256Digest(bits));
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Digest256 d = (Digest256)super.clone();
            d.digest = new LSH256Digest((LSH256Digest)digest);
            return d;
        }
    }

    public static class Digest224
        extends Digest256
    {
        public Digest224()
        {
            super(224);
        }
    }

    public static class Digest512
        extends BCMessageDigest
        implements Cloneable
    {
        public Digest512()
        {
            this(512);
        }

        Digest512(int bits)
        {
            super(new LSH512Digest(bits));
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Digest512 d = (Digest512)super.clone();
            d.digest = new LSH512Digest((LSH512Digest)digest);
            return d;
        }
    }

    public static class Digest384
        extends Digest512
    {
        public Digest384()
        {
            super(384);
        }
    }

    public static class Digest512_256
        extends Digest512
    {
        public Digest512_256()
        {
            super(256);
        }
    }

    public static class Digest512_224
        extends Digest512
    {
        public Digest512_224()
        {
            super(224);
        }
    }

    public static class HashMac224
        extends BaseMac
    {
        public HashMac224()
        {
            super(new HMac(new LSH256Digest(224)));
        }
    }

    public static class HashMac256
        extends BaseMac
    {
        public HashMac256()
        {
            super(new HMac(new LSH256Digest(256)));
        }
    }

    public static class HashMac384
        extends BaseMac
    {
        public HashMac384()
        {
            super(new HMac(new LSH512Digest(384)));
        }
    }

    public static class HashMac512
        extends BaseMac
    {
        public HashMac512()
        {
            super(new HMac(new LSH512Digest(512)));
        }
    }
}
