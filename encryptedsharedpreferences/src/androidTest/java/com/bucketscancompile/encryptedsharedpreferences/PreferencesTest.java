package com.bucketscancompile.encryptedsharedpreferences;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.bucketscancompile.encryptedsharedpreferences.crypto.CryptoException;
import com.bucketscancompile.encryptedsharedpreferences.utils.Logging;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

@RunWith(AndroidJUnit4.class)
public class PreferencesTest {

    private final static String PREFS_NAME = "ESPTestPrefs";
    private final static String KEY_STRING = "A123";
    private final static String KEY_INT = "B_45";
    private final static String KEY_BOOLEAN = "67C";
    private final static String KEY_FLOAT = "89DE~";
    private final static String KEY_LONG = "000";
    private final static String KEY_STRING_SET = "//^^123123ABCabc```";

    private final static int BENCHMARK_CYCLES = 100;

    @BeforeClass
    public static void enableLogging() {
        Logging.create(true);
    }

    private final EncryptedSharedPreferencesSettings settingsAesKeyOnDemand = new EncryptedSharedPreferencesSettings() {
        public Context context() { return InstrumentationRegistry.getTargetContext(); }
        public String preferencesName() { return PREFS_NAME; }
        public boolean allowCryptoKeyChange() { return true; }
        public boolean allowInsecureRSAFallback() { return true; }
        public boolean allowAesKeyInMemory() { return false; }
        public boolean allowDebugLogs() { return true; }
    };

    private final EncryptedSharedPreferencesSettings settingsAesKeyInMemory = new EncryptedSharedPreferencesSettings() {
        public Context context() { return InstrumentationRegistry.getTargetContext(); }
        public String preferencesName() { return PREFS_NAME; }
        public boolean allowCryptoKeyChange() { return true; }
        public boolean allowInsecureRSAFallback() { return true; }
        public boolean allowAesKeyInMemory() { return true; }
        public boolean allowDebugLogs() { return true; }
    };

    // test storage, retrieval and deletion
    @Test
    public void bulkTestWithAesKeyInMemory() throws CryptoException {
        final EncryptedSharedPreferences prefs = new EncryptedSharedPreferences(settingsAesKeyInMemory);

        bulkTestBackend(prefs);
    }

    // test storage, retrieval and deletion
    @Test
    public void bulkTestWithAesKeyOnDemand() throws CryptoException {
        final EncryptedSharedPreferences prefs = new EncryptedSharedPreferences(settingsAesKeyOnDemand);

        bulkTestBackend(prefs);
    }

    private void bulkTestBackend(EncryptedSharedPreferences prefs) {
        final List<String> stringList = new ArrayList<>(4);
        stringList.add("test1");
        stringList.add("test___-----99990");
        stringList.add("test3");
        stringList.add("4.1");

        final List<String> defaultStringList = new ArrayList<>(1);
        defaultStringList.add("NOTHING");

        final EncryptedSharedPreferences.Editor editor1 = prefs.edit();
        editor1.putString(KEY_STRING, "abc!!!...321");
        editor1.putInt(KEY_INT, 9981);
        editor1.putBoolean(KEY_BOOLEAN, true);
        editor1.putFloat(KEY_FLOAT, 3.14f);
        editor1.putLong(KEY_LONG, 912912912L);
        editor1.putStringSet(KEY_STRING_SET, new HashSet<>(stringList));
        editor1.commit();

        assertEquals("String", "abc!!!...321", prefs.getString(KEY_STRING, ""));
        assertEquals("Int",9981, prefs.getInt(KEY_INT, -1));
        assertEquals("Boolean", true, prefs.getBoolean(KEY_BOOLEAN, false));
        assertEquals("Float", 3.14f, prefs.getFloat(KEY_FLOAT, 1.1f), 0);
        assertEquals("Long", 912912912L, prefs.getLong(KEY_LONG, 2L));
        for (String actualString : prefs.getStringSet(KEY_STRING_SET, new HashSet<>(defaultStringList)))
            assertEquals("String set contains" + actualString, true, stringList.contains(actualString));

        final EncryptedSharedPreferences.Editor editor2 = prefs.edit();
        editor2.remove(KEY_STRING);
        editor2.remove(KEY_INT);
        editor2.remove(KEY_BOOLEAN);
        editor2.remove(KEY_FLOAT);
        editor2.remove(KEY_LONG);
        editor2.remove(KEY_STRING_SET);
        editor2.commit();

        assertFalse("String should not exist", prefs.contains(KEY_STRING));
        assertFalse("Int should not exist", prefs.contains(KEY_INT));
        assertFalse("Boolean should not exist", prefs.contains(KEY_BOOLEAN));
        assertFalse("Float should not exist", prefs.contains(KEY_FLOAT));
        assertFalse("Long should not exist", prefs.contains(KEY_LONG));
        assertFalse("String set should not exist", prefs.contains(KEY_STRING_SET));
    }

    @Ignore
    @Test
    public void timingWithAesKeyOnDemand() throws CryptoException {
        System.out.println("Starting ESP benchmark with AES key decrpyted on demand");

        // automatically generate crypto keys if necessary
        final EncryptedSharedPreferences prefs = new EncryptedSharedPreferences(settingsAesKeyOnDemand);

        timingBackend(prefs);
    }

    @Ignore
    @Test
    public void timingWithAesKeyInMemory() throws CryptoException {
        System.out.println("Starting ESP benchmark with decrypted AES key stored in memory");

        // automatically generate crypto keys if necessary
        final EncryptedSharedPreferences prefs = new EncryptedSharedPreferences(settingsAesKeyInMemory);

        timingBackend(prefs);
    }

    private void timingBackend(EncryptedSharedPreferences prefs) {
        final List<String> stringList = new ArrayList<>(4);
        stringList.add("test1");
        stringList.add("test___-----99990");
        stringList.add("test3");
        stringList.add("4.1");

        final List<String> defaultStringList = new ArrayList<>(1);
        defaultStringList.add("NOTHING");

        long storageStartTime, storageEndTime, retrievalStartTime, retrievalEndTime;

        storageStartTime = System.currentTimeMillis();
        for (int i = 0; i < BENCHMARK_CYCLES; i++) {
            final EncryptedSharedPreferences.Editor editor = prefs.edit();
            editor.putString(KEY_STRING, "abc!!!...321");
            editor.putInt(KEY_INT, 9981);
            editor.putBoolean(KEY_BOOLEAN, true);
            editor.putFloat(KEY_FLOAT, 3.14f);
            editor.putLong(KEY_LONG, 912912912L);
            editor.putStringSet(KEY_STRING_SET, new HashSet<>(stringList));
            editor.commit();
        }
        storageEndTime = System.currentTimeMillis();

        final float averageStorageTime = (float)(storageEndTime - storageStartTime) / BENCHMARK_CYCLES;
        System.out.println("ESP store average (" + BENCHMARK_CYCLES + " cycles): " + averageStorageTime);

        retrievalStartTime = System.currentTimeMillis();
        for (int i = 0; i < BENCHMARK_CYCLES; i++) {
            prefs.getString(KEY_STRING, "");
            prefs.getInt(KEY_INT, -1);
            prefs.getBoolean(KEY_BOOLEAN, false);
            prefs.getLong(KEY_LONG, 2L);
            prefs.getFloat(KEY_FLOAT, 1.1f);
            prefs.getStringSet(KEY_STRING_SET, new HashSet<>(defaultStringList));
        }
        retrievalEndTime = System.currentTimeMillis();

        final float averageRetrievalTime = (float)(retrievalEndTime - retrievalStartTime) / BENCHMARK_CYCLES;
        System.out.println("ESP retrieve average (" + BENCHMARK_CYCLES + " cycles): " + averageRetrievalTime);

        System.out.println("ESP benchmark completed");
    }

}