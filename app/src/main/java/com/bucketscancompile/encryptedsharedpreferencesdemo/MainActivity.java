package com.bucketscancompile.encryptedsharedpreferencesdemo;

import android.content.Context;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.bucketscancompile.encryptedsharedpreferences.EncryptedSharedPreferences;
import com.bucketscancompile.encryptedsharedpreferences.EncryptedSharedPreferencesSettings;
import com.bucketscancompile.encryptedsharedpreferences.crypto.CryptoException;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    private static final String PREFS_NAME = "MyEncPrefs";

    final EncryptedSharedPreferencesSettings mEncPrefsSettings = new EncryptedSharedPreferencesSettings() {
        public Context context() { return MainActivity.this; }
        public String preferencesName() { return PREFS_NAME; }
        public boolean allowCryptoKeyChange() { return false; }
        public boolean allowInsecureRSAFallback() { return true; }
        public boolean allowAesKeyInMemory() { return true; }
        public boolean allowDebugLogs() { return true; }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        new Thread(new Runnable() {
            @Override
            public void run() {
                doStuff();
            }
        }).start();

    }

    private void doStuff() {
        try {
            final EncryptedSharedPreferences prefs = new EncryptedSharedPreferences(mEncPrefsSettings);

            EncryptedSharedPreferences.Editor editor = prefs.edit();
            editor.putString("TestString", "This is my test string");
            editor.putBoolean("TestBoolean", true);
            editor.commit();

            Log.d(TAG, "String retrieved as " + prefs.getString("TestString", "NULL"));
            Log.d(TAG, "Boolean retrieved as " + prefs.getBoolean("TestBoolean", false));

        } catch (CryptoException ex) {
            Log.e(TAG, "Something went horribly wrong", ex);
        }
    }
}
