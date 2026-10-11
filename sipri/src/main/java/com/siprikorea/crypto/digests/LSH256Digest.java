package com.siprikorea.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * LSH-256 family hash function (KS X 3262), producing 224 or 256-bit digests.
 * <p>
 * LSH is the Korean national standard hash function designed by NSR. The 256-bit
 * wide-pipe variant operates on 32-bit words and 128-byte message blocks.
 * </p>
 */
public class LSH256Digest
    implements ExtendedDigest, Memoable
{
    private static final int BLOCK_SIZE = 128;
    private static final int NUM_STEPS = 26;

    private static final int ROT_EVEN_ALPHA = 29;
    private static final int ROT_EVEN_BETA = 1;
    private static final int ROT_ODD_ALPHA = 5;
    private static final int ROT_ODD_BETA = 17;

    private static final int[] GAMMA = { 0, 8, 16, 24, 24, 16, 8, 0 };

    private static final int[] IV224 = {
        0x068608d3, 0x62d8f7a7, 0xd76652ab, 0x4c600a43, 0xbdc40aa8, 0x1eca0b68, 0xda1a89be, 0x3147d354,
        0x707eb4f9, 0xf65b3862, 0x6b0b2abe, 0x56b8ec0a, 0xcf237286, 0xee0d1727, 0x33636595, 0x8bb8d05f
    };

    private static final int[] IV256 = {
        0x46a10f1f, 0xfddce486, 0xb41443a8, 0x198e6b9d, 0x3304388d, 0xb0f5a3c7, 0xb36061c4, 0x7adbd553,
        0x105d5378, 0x2f74de54, 0x5c2f2d95, 0xf2553fbe, 0x8051357a, 0x138668c8, 0x47aa4484, 0xe01afb41
    };

    private static final int[] STEP_CONSTANTS = {
        0x917caf90, 0x6c1b10a2, 0x6f352943, 0xcf778243, 0x2ceb7472, 0x29e96ff2, 0x8a9ba428, 0x2eeb2642,
        0x0e2c4021, 0x872bb30e, 0xa45e6cb2, 0x46f9c612, 0x185fe69e, 0x1359621b, 0x263fccb2, 0x1a116870,
        0x3a6c612f, 0xb2dec195, 0x02cb1f56, 0x40bfd858, 0x784684b6, 0x6cbb7d2e, 0x660c7ed8, 0x2b79d88a,
        0xa6cd9069, 0x91a05747, 0xcdea7558, 0x00983098, 0xbecb3b2e, 0x2838ab9a, 0x728b573e, 0xa55262b5,
        0x745dfa0f, 0x31f79ed8, 0xb85fce25, 0x98c8c898, 0x8a0669ec, 0x60e445c2, 0xfde295b0, 0xf7b5185a,
        0xd2580983, 0x29967709, 0x182df3dd, 0x61916130, 0x90705676, 0x452a0822, 0xe07846ad, 0xaccd7351,
        0x2a618d55, 0xc00d8032, 0x4621d0f5, 0xf2f29191, 0x00c6cd06, 0x6f322a67, 0x58bef48d, 0x7a40c4fd,
        0x8beee27f, 0xcd8db2f2, 0x67f2c63b, 0xe5842383, 0xc793d306, 0xa15c91d6, 0x17b381e5, 0xbb05c277,
        0x7ad1620a, 0x5b40a5bf, 0x5ab901a2, 0x69a7a768, 0x5b66d9cd, 0xfdee6877, 0xcb3566fc, 0xc0c83a32,
        0x4c336c84, 0x9be6651a, 0x13baa3fc, 0x114f0fd1, 0xc240a728, 0xec56e074, 0x009c63c7, 0x89026cf2,
        0x7f9ff0d0, 0x824b7fb5, 0xce5ea00f, 0x605ee0e2, 0x02e7cfea, 0x43375560, 0x9d002ac7, 0x8b6f5f7b,
        0x1f90c14f, 0xcdcb3537, 0x2cfeafdd, 0xbf3fc342, 0xeab7b9ec, 0x7a8cb5a3, 0x9d2af264, 0xfacedb06,
        0xb052106e, 0x99006d04, 0x2bae8d09, 0xff030601, 0xa271a6d6, 0x0742591d, 0xc81d5701, 0xc9a9e200,
        0x02627f1e, 0x996d719d, 0xda3b9634, 0x02090800, 0x14187d78, 0x499b7624, 0xe57458c9, 0x738be2c9,
        0x64e19d20, 0x06df0f36, 0x15d1cb0e, 0x0b110802, 0x2c95f58c, 0xe5119a6d, 0x59cd22ae, 0xff6eac3c,
        0x467ebd84, 0xe5ee453c, 0xe79cd923, 0x1c190a0d, 0xc28b81b8, 0xf6ac0852, 0x26efd107, 0x6e1ae93b,
        0xc53c41ca, 0xd4338221, 0x8475fd0a, 0x35231729, 0x4e0d3a7a, 0xa2b45b48, 0x16c0d82d, 0x890424a9,
        0x017e0c8f, 0x07b5a3f5, 0xfa73078e, 0x583a405e, 0x5b47b4c8, 0x570fa3ea, 0xd7990543, 0x8d28ce32,
        0x7f8a9b90, 0xbd5998fc, 0x6d7a9688, 0x927a9eb6, 0xa2fc7d23, 0x66b38e41, 0x709e491a, 0xb5f700bf,
        0x0a262c0f, 0x16f295b9, 0xe8111ef5, 0x0d195548, 0x9f79a0c5, 0x1a41cfa7, 0x0ee7638a, 0xacf7c074,
        0x30523b19, 0x09884ecf, 0xf93014dd, 0x266e9d55, 0x191a6664, 0x5c1176c1, 0xf64aed98, 0xa4b83520,
        0x828d5449, 0x91d71dd8, 0x2944f2d6, 0x950bf27b, 0x3380ca7d, 0x6d88381d, 0x4138868e, 0x5ced55c4,
        0x0fe19dcb, 0x68f4f669, 0x6e37c8ff, 0xa0fe6e10, 0xb44b47b0, 0xf5c0558a, 0x79bf14cf, 0x4a431a20,
        0xf17f68da, 0x5deb5fd1, 0xa600c86d, 0x9f6c7eb0, 0xff92f864, 0xb615e07f, 0x38d3e448, 0x8d5d3a6a,
        0x70e843cb, 0x494b312e, 0xa6c93613, 0x0beb2f4f, 0x928b5d63, 0xcbf66035, 0x0cb82c80, 0xea97a4f7,
        0x592c0f3b, 0x947c5f77, 0x6fff49b9, 0xf71a7e5a, 0x1de8c0f5, 0xc2569600, 0xc4e4ac8c, 0x823c9ce1

    };

    private final int digestSize;
    private final int[] iv;

    private final int[] cvL = new int[8];
    private final int[] cvR = new int[8];
    // even-left, even-right, odd-left, odd-right sub-messages, 8 words each
    private final int[] subMsgs = new int[32];
    private final byte[] buf = new byte[BLOCK_SIZE];
    private int bufOff;

    /**
     * Construct an LSH-256 digest with the full 256-bit output.
     */
    public LSH256Digest()
    {
        this(256);
    }

    /**
     * Construct an LSH-256 digest.
     *
     * @param bitLength the digest length in bits, one of 224 or 256.
     */
    public LSH256Digest(int bitLength)
    {
        this.digestSize = bitLength / 8;
        this.iv = ivFor(bitLength);

        reset();
    }

    /**
     * Copy constructor.
     *
     * @param t the digest whose state is copied.
     */
    public LSH256Digest(LSH256Digest t)
    {
        this.digestSize = t.digestSize;
        this.iv = t.iv;

        reset(t);
    }

    private static int[] ivFor(int bitLength)
    {
        switch (bitLength)
        {
        case 224:
            return IV224;
        case 256:
            return IV256;
        default:
            throw new IllegalArgumentException("LSH-256 digest length must be one of 224 or 256 bits");
        }
    }

    public String getAlgorithmName()
    {
        return "LSH-" + (digestSize * 8);
    }

    public int getDigestSize()
    {
        return digestSize;
    }

    public int getByteLength()
    {
        return BLOCK_SIZE;
    }

    public void update(byte in)
    {
        buf[bufOff++] = in;
        if (bufOff == BLOCK_SIZE)
        {
            compress(buf, 0);
            bufOff = 0;
        }
    }

    public void update(byte[] in, int inOff, int len)
    {
        if (bufOff != 0)
        {
            int n = Math.min(BLOCK_SIZE - bufOff, len);
            System.arraycopy(in, inOff, buf, bufOff, n);
            bufOff += n;
            inOff += n;
            len -= n;
            if (bufOff < BLOCK_SIZE)
            {
                return;
            }
            compress(buf, 0);
            bufOff = 0;
        }

        while (len >= BLOCK_SIZE)
        {
            compress(in, inOff);
            inOff += BLOCK_SIZE;
            len -= BLOCK_SIZE;
        }

        System.arraycopy(in, inOff, buf, 0, len);
        bufOff = len;
    }

    public int doFinal(byte[] out, int outOff)
    {
        buf[bufOff] = (byte)0x80;
        Arrays.fill(buf, bufOff + 1, BLOCK_SIZE, (byte)0);
        compress(buf, 0);

        byte[] h = new byte[4 * 8];
        for (int i = 0; i < 8; ++i)
        {
            Pack.intToLittleEndian(cvL[i] ^ cvR[i], h, i * 4);
        }
        System.arraycopy(h, 0, out, outOff, digestSize);
        Arrays.fill(h, (byte)0);

        reset();

        return digestSize;
    }

    public void reset()
    {
        System.arraycopy(iv, 0, cvL, 0, 8);
        System.arraycopy(iv, 8, cvR, 0, 8);
        Arrays.fill(subMsgs, 0);
        Arrays.fill(buf, (byte)0);
        bufOff = 0;
    }

    public Memoable copy()
    {
        return new LSH256Digest(this);
    }

    public void reset(Memoable other)
    {
        LSH256Digest d = (LSH256Digest)other;
        if (d.digestSize != digestSize)
        {
            throw new IllegalArgumentException("digest length mismatch in reset()");
        }

        System.arraycopy(d.cvL, 0, cvL, 0, 8);
        System.arraycopy(d.cvR, 0, cvR, 0, 8);
        System.arraycopy(d.subMsgs, 0, subMsgs, 0, 32);
        System.arraycopy(d.buf, 0, buf, 0, BLOCK_SIZE);
        bufOff = d.bufOff;
    }

    private void compress(byte[] block, int off)
    {
        for (int i = 0; i < 32; ++i)
        {
            subMsgs[i] = Pack.littleEndianToInt(block, off + i * 4);
        }

        msgAdd(0);
        mix(ROT_EVEN_ALPHA, ROT_EVEN_BETA, 0);
        wordPerm();
        msgAdd(16);
        mix(ROT_ODD_ALPHA, ROT_ODD_BETA, 8);
        wordPerm();

        for (int i = 1; i < NUM_STEPS / 2; ++i)
        {
            msgExp(0, 16);
            msgAdd(0);
            mix(ROT_EVEN_ALPHA, ROT_EVEN_BETA, 16 * i);
            wordPerm();
            msgExp(16, 0);
            msgAdd(16);
            mix(ROT_ODD_ALPHA, ROT_ODD_BETA, 16 * i + 8);
            wordPerm();
        }

        msgExp(0, 16);
        msgAdd(0);
    }

    /**
     * Message expansion: the sub-message pair at dst (left at dst, right at dst + 8) is replaced
     * by (other + permuted(dst)), where other is the pair at src.
     */
    private void msgExp(int dst, int src)
    {
        for (int half = 0; half < 16; half += 8)
        {
            int d = dst + half, s = src + half;
            int t = subMsgs[d];
            subMsgs[d] = subMsgs[s] + subMsgs[d + 3];
            subMsgs[d + 3] = subMsgs[s + 3] + subMsgs[d + 1];
            subMsgs[d + 1] = subMsgs[s + 1] + subMsgs[d + 2];
            subMsgs[d + 2] = subMsgs[s + 2] + t;
            t = subMsgs[d + 4];
            subMsgs[d + 4] = subMsgs[s + 4] + subMsgs[d + 7];
            subMsgs[d + 7] = subMsgs[s + 7] + subMsgs[d + 6];
            subMsgs[d + 6] = subMsgs[s + 6] + subMsgs[d + 5];
            subMsgs[d + 5] = subMsgs[s + 5] + t;
        }
    }

    private void msgAdd(int src)
    {
        for (int i = 0; i < 8; ++i)
        {
            cvL[i] ^= subMsgs[src + i];
            cvR[i] ^= subMsgs[src + 8 + i];
        }
    }

    private void mix(int alpha, int beta, int scOff)
    {
        for (int i = 0; i < 8; ++i)
        {
            int l = cvL[i] + cvR[i];
            l = Integer.rotateLeft(l, alpha) ^ STEP_CONSTANTS[scOff + i];
            int r = Integer.rotateLeft(cvR[i] + l, beta);
            cvL[i] = l + r;
            cvR[i] = Integer.rotateLeft(r, GAMMA[i]);
        }
    }

    private void wordPerm()
    {
        int t = cvL[0];
        cvL[0] = cvL[6];
        cvL[6] = cvR[6];
        cvR[6] = cvR[2];
        cvR[2] = cvL[1];
        cvL[1] = cvL[4];
        cvL[4] = cvR[4];
        cvR[4] = cvR[0];
        cvR[0] = cvL[2];
        cvL[2] = cvL[5];
        cvL[5] = cvR[7];
        cvR[7] = cvR[1];
        cvR[1] = t;
        t = cvL[3];
        cvL[3] = cvL[7];
        cvL[7] = cvR[5];
        cvR[5] = cvR[3];
        cvR[3] = t;
    }
}
