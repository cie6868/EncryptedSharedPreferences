package com.bucketscancompile.encryptedsharedpreferences.utils;

import android.support.annotation.Nullable;

import java.util.Arrays;

/**
 * Quick and dirty memory wipes. May or may not work depending on the JVM's garbage collection.
 */
public class Wipe {

    public static void bytes(@Nullable byte[] array) {
        if (array != null)
            Arrays.fill(array, (byte)0);
    }

}
