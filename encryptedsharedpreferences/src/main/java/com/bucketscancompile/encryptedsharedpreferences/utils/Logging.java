package com.bucketscancompile.encryptedsharedpreferences.utils;

import android.util.Log;

public class Logging {

    private static Logging instance;

    private final boolean mAllowLogging;

    private Logging(boolean allowLogging) {
        mAllowLogging = allowLogging;
    }

    public static void create(boolean allowLogging) {
        if (instance == null)
            instance = new Logging(allowLogging);
    }

    public static Logging getInstance() {
        if (instance == null)
            create(false);      // default to no logging
        return instance;
    }

    public void d(String tag, String message) {
        if (mAllowLogging)
            Log.d(tag, message);
    }

    public void d(String tag, String message, Throwable exception) {
        if (mAllowLogging)
            Log.d(tag, message, exception);
    }

    public void e(String tag, String message) {
        if (mAllowLogging)
            Log.e(tag, message);
    }

    public void e(String tag, String message, Throwable exception) {
        if (mAllowLogging)
            Log.e(tag, message, exception);
    }

}
