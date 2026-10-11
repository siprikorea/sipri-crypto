package com.siprikorea.crypto.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.util.encoders.Hex;

/**
 * Reader for the test vector files under {@code vectors/}: blank-line or '#' separated groups of
 * {@code Name: value} (Crypto++ TestVectors format) or {@code Name = value} lines.
 */
final class VectorFile
{
    private VectorFile()
    {
    }

    static List<Map<String, String>> load(String name)
        throws IOException
    {
        InputStream in = VectorFile.class.getResourceAsStream("vectors/" + name);
        if (in == null)
        {
            throw new IOException("missing test resource vectors/" + name);
        }

        List<Map<String, String>> groups = new ArrayList<Map<String, String>>();
        Map<String, String> header = new LinkedHashMap<String, String>();
        Map<String, String> cur = new LinkedHashMap<String, String>();

        BufferedReader r = new BufferedReader(new InputStreamReader(in, "UTF-8"));
        try
        {
            String line;
            while ((line = r.readLine()) != null)
            {
                line = line.trim();
                if (line.length() == 0 || line.startsWith("#"))
                {
                    flush(groups, header, cur);
                    continue;
                }

                int colon = line.indexOf(':');
                int eq = line.indexOf('=');
                int sep = (colon < 0) ? eq : (eq < 0 ? colon : Math.min(colon, eq));
                if (sep < 0)
                {
                    continue;
                }
                String key = line.substring(0, sep).trim();
                String value = line.substring(sep + 1).trim();

                // Crypto++ files carry the algorithm name in a header group of its own
                if (key.equals("Name") || key.equals("AlgorithmType") || key.equals("Source"))
                {
                    header.put(key, value);
                }
                else
                {
                    cur.put(key, value);
                }
            }
            flush(groups, header, cur);
        }
        finally
        {
            r.close();
        }

        return groups;
    }

    private static void flush(List<Map<String, String>> groups, Map<String, String> header, Map<String, String> cur)
    {
        if (!cur.isEmpty())
        {
            Map<String, String> g = new LinkedHashMap<String, String>(header);
            g.putAll(cur);
            groups.add(g);
            cur.clear();
        }
    }

    /**
     * Decode a hex value, accepting embedded whitespace and the Crypto++ "rN xx" repeat form.
     */
    static byte[] hex(String value)
    {
        value = value.trim();
        if (value.startsWith("r"))
        {
            int sp = value.indexOf(' ');
            int count = Integer.parseInt(value.substring(1, sp));
            byte[] unit = Hex.decode(value.substring(sp + 1).replaceAll("\\s", ""));
            byte[] out = new byte[count * unit.length];
            for (int i = 0; i < count; i++)
            {
                System.arraycopy(unit, 0, out, i * unit.length, unit.length);
            }
            return out;
        }
        return Hex.decode(value.replaceAll("\\s", ""));
    }
}
