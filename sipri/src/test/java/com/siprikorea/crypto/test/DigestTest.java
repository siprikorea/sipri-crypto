package com.siprikorea.crypto.test;

import java.util.List;
import java.util.Map;

import com.siprikorea.crypto.digests.HAS160Digest;
import com.siprikorea.crypto.digests.LSH256Digest;
import com.siprikorea.crypto.digests.LSH512Digest;
import junit.framework.TestCase;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Known-answer tests for LSH (Crypto++ TestVectors, generated with the KISA reference code) and
 * HAS-160 (TTAS.KO-12.0011/R2 sample values).
 */
public class DigestTest
    extends TestCase
{
    public void testLSH224()
        throws Exception
    {
        int n = checkFile("lsh256.txt", "LSH-224", new LSH256Digest(224));
        assertTrue(n > 100);
    }

    public void testLSH256()
        throws Exception
    {
        int n = checkFile("lsh256.txt", "LSH-256", new LSH256Digest(256));
        assertTrue(n > 100);
    }

    public void testLSH384()
        throws Exception
    {
        int n = checkFile("lsh512.txt", "LSH-384", new LSH512Digest(384));
        assertTrue(n > 100);
    }

    public void testLSH512()
        throws Exception
    {
        int n = checkFile("lsh512.txt", "LSH-512", new LSH512Digest(512));
        assertTrue(n > 100);
    }

    public void testLSH512_256()
        throws Exception
    {
        int n = checkFile("lsh512_256.txt", "LSH-512-256", new LSH512Digest(256));
        assertTrue(n > 100);
    }

    public void testLSH512_224Distinct()
    {
        // no published vectors in the files above: check it is wired to its own IV and length
        byte[] a = digest(new LSH512Digest(224), new byte[0]);
        byte[] b = digest(new LSH512Digest(256), new byte[0]);
        assertEquals(28, a.length);
        assertFalse(Hex.toHexString(b).startsWith(Hex.toHexString(a)));
        assertEquals("LSH-512-224", new LSH512Digest(224).getAlgorithmName());
    }

    public void testInvalidLengths()
    {
        try
        {
            new LSH256Digest(384);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        try
        {
            new LSH512Digest(160);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public void testHAS160()
    {
        String[][] v = {
            { "", "307964ef34151d37c8047adec7ab50f4ff89762d" },
            { "a", "4872bcbc4cd0f0a9dc7c2f7045e5b43b6c830db8" },
            { "abc", "975e810488cf2a3d49838478124afce4b1c78804" },
            { "message digest", "2338dbc8638d31225f73086246ba529f96710bc6" },
            { "abcdefghijklmnopqrstuvwxyz", "596185c9ab6703d0d0dbb98702bc0f5729cd1d3c" },
            { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "cb5d7efbca2f02e0fb7167cabb123af5795764e5" },
            { "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "07f05c8c0773c55ca3a5a695ce6aca4c438911b5" },
        };

        for (int i = 0; i < v.length; i++)
        {
            byte[] msg = Strings.toByteArray(v[i][0]);
            assertEquals(v[i][0], v[i][1], Hex.toHexString(digest(new HAS160Digest(), msg)));
            checkIncremental(new HAS160Digest(), msg, Hex.decode(v[i][1]));
        }

        HAS160Digest d = new HAS160Digest();
        byte[] block = new byte[1000];
        java.util.Arrays.fill(block, (byte)'a');
        for (int i = 0; i < 1000; i++)
        {
            d.update(block, 0, block.length);
        }
        byte[] out = new byte[20];
        d.doFinal(out, 0);
        assertEquals("d6ad6f0608b878da9b87999c2525cc84f4c9f18d", Hex.toHexString(out));
    }

    private int checkFile(String file, String name, Digest digest)
        throws Exception
    {
        List<Map<String, String>> groups = VectorFile.load(file);
        int count = 0;
        for (Map<String, String> g : groups)
        {
            if (!name.equals(g.get("Name")) || !g.containsKey("Digest"))
            {
                continue;
            }
            byte[] msg = VectorFile.hex(g.get("Message"));
            byte[] expected = VectorFile.hex(g.get("Digest"));

            byte[] actual = digest(digest, msg);
            assertEquals(name + " " + g.get("Comment"), Hex.toHexString(expected), Hex.toHexString(actual));
            checkIncremental(digest, msg, expected);
            count++;
        }
        return count;
    }

    private static byte[] digest(Digest d, byte[] msg)
    {
        byte[] out = new byte[d.getDigestSize()];
        d.update(msg, 0, msg.length);
        d.doFinal(out, 0);
        return out;
    }

    // byte-at-a-time, split updates, and a Memoable copy taken mid-stream must all agree
    private static void checkIncremental(Digest d, byte[] msg, byte[] expected)
    {
        for (int i = 0; i < msg.length; i++)
        {
            d.update(msg[i]);
        }
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        assertEquals(Hex.toHexString(expected), Hex.toHexString(out));

        int half = msg.length / 2;
        d.update(msg, 0, half);
        Digest copy = (Digest)((Memoable)d).copy();
        d.update(msg, half, msg.length - half);
        d.doFinal(out, 0);
        assertEquals(Hex.toHexString(expected), Hex.toHexString(out));

        copy.update(msg, half, msg.length - half);
        copy.doFinal(out, 0);
        assertEquals(Hex.toHexString(expected), Hex.toHexString(out));
    }
}
