package com.bucketscancompile.encryptedsharedpreferences;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.bucketscancompile.encryptedsharedpreferences.crypto.Crypto;
import com.bucketscancompile.encryptedsharedpreferences.crypto.CryptoException;
import com.bucketscancompile.encryptedsharedpreferences.crypto.KeyStorageLocation;
import com.bucketscancompile.encryptedsharedpreferences.utils.Logging;

import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

@RunWith(AndroidJUnit4.class)
public class RsaHelperTest {

    private final static String PLAINTEXT = "TestString1234```]]]_ *98//^^^^^";
    private static int BATCH_ELEMENTS = 10;
    private static int BENCHMARK_CYCLES = 100;

    @BeforeClass
    public static void enableLogging() {
        Logging.create(true);
    }

    @Test
    public void generateFreshKeyAndDelete() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();

        // delete any existing key
        final Crypto rsa1 = RsaHelper.getExistingCrypto(context, true);
        if (rsa1 != null) {
            rsa1.deleteKey();
            assertEquals("Key should not exist", false, rsa1.doesKeyExist());
        }

        final Crypto rsa2 = RsaHelper.generateCrypto(context, true);
        assertNotNull("RSA crypto should be available", rsa2);

        // confirm key exists
        assertEquals("Key should exist", true, rsa2.doesKeyExist());

        // delete key
        rsa2.deleteKey();
        assertEquals("Key should not exist", false, rsa2.doesKeyExist());

        final Crypto rsa3 = RsaHelper.getExistingCrypto(context, true);
        assertNull("RsaHelper should be null", rsa3);
    }

    @Test
    public void encryptAndDecryptBytes() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        Crypto rsa = RsaHelper.getExistingCrypto(context, true);

        // make sure keys exist
        if (rsa == null)
            rsa = RsaHelper.generateCrypto(context, true);
        assertNotNull("RsaHelper should not be null", rsa);
        assertEquals("Key should exist", true, rsa.doesKeyExist());

        final byte[] plaintextBytes = PLAINTEXT.getBytes();

        // encrypt and decrypt
        final byte[] encryptedBytes = rsa.encrypt(plaintextBytes);
        final byte[] decryptedBytes = rsa.decrypt(encryptedBytes);

        // check if output is same as input
        assertArrayEquals("Original and encrypted-decrypted output should be equal", plaintextBytes, decryptedBytes);
    }

    @Test
    public void encryptAndDecryptBytesBatch() throws CryptoException {
        final List<byte[]> plaintextBytesList = new ArrayList<>(BATCH_ELEMENTS);
        for (int i = 0; i < BATCH_ELEMENTS; i++)
            plaintextBytesList.add(PLAINTEXT.getBytes());
        final byte[][] plaintextBytesBatch = plaintextBytesList.toArray(new byte[plaintextBytesList.size()][]);

        final Context context = InstrumentationRegistry.getTargetContext();
        Crypto rsa = RsaHelper.getExistingCrypto(context, true);

        // make sure keys exist
        if (rsa == null)
            rsa = RsaHelper.generateCrypto(context, true);
        assertNotNull("RsaHelper should not be null", rsa);
        assertEquals("Key should exist", true, rsa.doesKeyExist());

        // encrypt and decrypt
        final byte[][] encryptedBytesBatch = rsa.encrypt(plaintextBytesBatch);
        final byte[][] decryptedBytesBatch = rsa.decrypt(encryptedBytesBatch);

        // check if output is same as input
        for (int i = 0; i < plaintextBytesBatch.length; i++)
            assertArrayEquals("Original and encrypted-decrypted output should be equal (index " + i + ")", plaintextBytesBatch[i], decryptedBytesBatch[i]);
    }

    @Test
    public void encryptAndDecryptString() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        Crypto rsa = RsaHelper.getExistingCrypto(context, true);

        // make sure keys exist
        if (rsa == null)
            rsa = RsaHelper.generateCrypto(context, true);
        assertNotNull("RsaHelper should not be null", rsa);
        assertEquals("Key should exist", true, rsa.doesKeyExist());

        // encrypt and decrypt
        final String encrypted = rsa.encrypt(PLAINTEXT);
        final String decrypted = rsa.decrypt(encrypted);

        // check if output is same as input
        assertEquals("Original and encrypted-decrypted output should be equal", PLAINTEXT, decrypted);
    }

    @Test
    public void encryptAndDecryptStringsBatch() throws CryptoException {
        final Set<String> plaintextStringsSet = new HashSet<>(BATCH_ELEMENTS);
        for (int i = 0; i < BATCH_ELEMENTS; i++)
            plaintextStringsSet.add(PLAINTEXT);

        final Context context = InstrumentationRegistry.getTargetContext();
        Crypto rsa = RsaHelper.getExistingCrypto(context, true);

        // make sure keys exist
        if (rsa == null)
            rsa = RsaHelper.generateCrypto(context, true);
        assertNotNull("RsaHelper should not be null", rsa);
        assertEquals("Key should exist", true, rsa.doesKeyExist());

        // encrypt and decrypt
        final Set<String> encryptedStringsBatch = rsa.encrypt(plaintextStringsSet);
        final Set<String> decryptedStringsBatch = rsa.decrypt(encryptedStringsBatch);

        // check if output is same as input
        assertEquals("Original and encrypted-decrypted output should be equal", plaintextStringsSet, decryptedStringsBatch);
    }

    @Ignore
    @Test
    public void timing() throws CryptoException {
        final Set<String> plaintextSet = new HashSet<>(BENCHMARK_CYCLES);
        for (int i = 0; i < BENCHMARK_CYCLES; i++)
            plaintextSet.add(PLAINTEXT);

        final Context context = InstrumentationRegistry.getTargetContext();
        Crypto rsa = RsaHelper.getExistingCrypto(context, true);

        // make sure keys exist
        if (rsa == null)
            rsa = RsaHelper.generateCrypto(context, true);
        assertNotNull("RSA crypto should be available", rsa);

        System.out.println("Starting RsaHelper benchmarks...");
        System.out.println(rsa.getKeyStorageLocation() == KeyStorageLocation.SECURE ? "RSA is being processed in TEE" : "RSA is processed in software");

        long startTime, endTime;
        float average;

        // encrypt
        String encrypted = "";
        startTime = System.currentTimeMillis();
        for (int i = 0; i < BENCHMARK_CYCLES; i++)
            encrypted = rsa.encrypt(PLAINTEXT);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / BENCHMARK_CYCLES;
        System.out.println("Encryption average time (" + BENCHMARK_CYCLES + " cycles): " + average);

        // decrypt batch
        startTime = System.currentTimeMillis();
        for (int i = 0; i < BENCHMARK_CYCLES; i++)
            rsa.decrypt(encrypted);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / BENCHMARK_CYCLES;
        System.out.println("Decryption average time (" + BENCHMARK_CYCLES + " cycles): " + average);

        // encrypt batch
        startTime = System.currentTimeMillis();
        Set<String> encryptedBatch = rsa.encrypt(plaintextSet);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / BENCHMARK_CYCLES;
        System.out.println("Encryption average time (" + BENCHMARK_CYCLES + " cycles): batch " + average);

        // decrypt batch
        startTime = System.currentTimeMillis();
        rsa.decrypt(encryptedBatch);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / BENCHMARK_CYCLES;
        System.out.println("Decryption average time (" + BENCHMARK_CYCLES + " cycles): batch " + average);

        System.out.println("RsaHelper benchmarks completed");
    }

}