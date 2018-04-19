package com.bucketscancompile.encryptedsharedpreferences.utils;

/**
 * Adapted from <a href="http://grepcode.com/file_/repo1.maven.org/maven2/com.madgag.spongycastle/core/1.52.0.0/org/spongycastle/util/Arrays.java/?v=source">org.spongycastle.util.Arrays.concatenate</a>.
 */
public class Arrays {

    public static byte[] concatenate(byte[] a, byte[] b)
    {
        if (a != null && b != null)
        {
            byte[] rv = new byte[a.length + b.length];

            System.arraycopy(a, 0, rv, 0, a.length);
            System.arraycopy(b, 0, rv, a.length, b.length);

            return rv;
        }
        else if (b != null)
        {
            return clone(b);
        }
        else
        {
            return clone(a);
        }
    }

    private static byte[] clone(byte[] data)
    {
        if (data == null)
        {
            return null;
        }
        byte[] copy = new byte[data.length];

        System.arraycopy(data, 0, copy, 0, data.length);

        return copy;
    }

}
