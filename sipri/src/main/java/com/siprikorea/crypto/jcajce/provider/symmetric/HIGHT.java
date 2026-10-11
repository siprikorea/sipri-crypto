package com.siprikorea.crypto.jcajce.provider.symmetric;

import java.security.AlgorithmParameters;
import java.security.Provider;

import javax.crypto.spec.IvParameterSpec;

import com.siprikorea.crypto.engines.HIGHTEngine;
import com.siprikorea.crypto.jcajce.provider.SipriCryptoProvider;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

/**
 * JCA/JCE services for the HIGHT block cipher. The mode and padding come from the transformation
 * string ("HIGHT/CBC/PKCS5Padding", "HIGHT/CTR/NoPadding", ...), handled by the Bouncy Castle
 * {@link BaseBlockCipher}.
 */
public final class HIGHT
{
    private HIGHT()
    {
    }

    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new HIGHTEngine();
                }
            });
        }

        /**
         * The Bouncy Castle base class would look "HIGHT" parameters up in the BC provider, which
         * has none; build them from this provider's own AlgorithmParameters service instead.
         */
        protected AlgorithmParameters engineGetParameters()
        {
            byte[] iv = engineGetIV();
            if (iv == null)
            {
                return null;
            }

            try
            {
                AlgorithmParameters params = AlgorithmParameters.getInstance("HIGHT", ProviderHolder.PROVIDER);
                params.init(new IvParameterSpec(iv));
                return params;
            }
            catch (Exception e)
            {
                throw new IllegalStateException("unable to create HIGHT parameters: " + e.toString());
            }
        }
    }

    private static final class ProviderHolder
    {
        static final Provider PROVIDER = new SipriCryptoProvider();
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("HIGHT", 128, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "HIGHT IV";
        }
    }

    public static class Mac
        extends BaseMac
    {
        public Mac()
        {
            super(new CMac(new HIGHTEngine()));
        }
    }
}
