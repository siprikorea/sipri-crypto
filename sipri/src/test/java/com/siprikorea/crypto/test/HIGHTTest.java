package com.siprikorea.crypto.test;

import java.util.List;
import java.util.Map;

import com.siprikorea.crypto.engines.HIGHTEngine;
import junit.framework.TestCase;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

/**
 * HIGHT known-answer tests - ECB, CBC and CTR vectors from the KISA reference code
 * (KISA_HIGHT_ECB.c / _CBC.c / _CTR.c, as collected in Crypto++ TestVectors/hight.txt).
 */
public class HIGHTTest
    extends TestCase
{
    public void testVectors()
        throws Exception
    {
        List<Map<String, String>> groups = VectorFile.load("hight.txt");
        int ecb = 0, cbc = 0, ctr = 0;

        for (Map<String, String> g : groups)
        {
            String name = g.get("Name");
            byte[] key = VectorFile.hex(g.get("Key"));
            byte[] pt = VectorFile.hex(g.get("Plaintext"));
            byte[] ct = VectorFile.hex(g.get("Ciphertext"));

            if ("HIGHT/ECB".equals(name))
            {
                checkBlock(new HIGHTEngine(), new KeyParameter(key), pt, ct);
                ecb++;
            }
            else if ("HIGHT/CBC".equals(name))
            {
                ParametersWithIV p = new ParametersWithIV(new KeyParameter(key), VectorFile.hex(g.get("IV")));
                checkBlock(CBCBlockCipher.newInstance(new HIGHTEngine()), p, pt, ct);
                cbc++;
            }
            else if ("HIGHT/CTR".equals(name))
            {
                ParametersWithIV p = new ParametersWithIV(new KeyParameter(key), VectorFile.hex(g.get("IV")));
                StreamCipher c = (StreamCipher)SICBlockCipher.newInstance(new HIGHTEngine());
                byte[] out = new byte[pt.length];
                c.init(true, p);
                c.processBytes(pt, 0, pt.length, out, 0);
                assertEquals(Hex.toHexString(ct), Hex.toHexString(out));
                c.init(false, p);
                c.processBytes(ct, 0, ct.length, out, 0);
                assertEquals(Hex.toHexString(pt), Hex.toHexString(out));
                ctr++;
            }
        }

        assertEquals(15, ecb);
        assertEquals(8, cbc);
        assertEquals(52, ctr);
    }

    public void testKeySize()
    {
        try
        {
            new HIGHTEngine().init(true, new KeyParameter(new byte[24]));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("HIGHT key must be 128 bits", e.getMessage());
        }
    }

    private static void checkBlock(BlockCipher c, org.bouncycastle.crypto.CipherParameters p, byte[] pt, byte[] ct)
    {
        int bs = c.getBlockSize();
        byte[] out = new byte[pt.length];

        c.init(true, p);
        for (int i = 0; i < pt.length; i += bs)
        {
            c.processBlock(pt, i, out, i);
        }
        assertEquals(Hex.toHexString(ct), Hex.toHexString(out));

        c.init(false, p);
        for (int i = 0; i < ct.length; i += bs)
        {
            c.processBlock(ct, i, out, i);
        }
        assertEquals(Hex.toHexString(pt), Hex.toHexString(out));
    }
}
