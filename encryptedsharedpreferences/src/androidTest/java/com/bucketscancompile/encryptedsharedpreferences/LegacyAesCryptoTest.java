package com.bucketscancompile.encryptedsharedpreferences;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.bucketscancompile.encryptedsharedpreferences.crypto.Crypto;
import com.bucketscancompile.encryptedsharedpreferences.crypto.CryptoException;
import com.bucketscancompile.encryptedsharedpreferences.crypto.KeyStorageLocation;
import com.bucketscancompile.encryptedsharedpreferences.crypto.LegacyAesCrypto;
import com.bucketscancompile.encryptedsharedpreferences.utils.Logging;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@RunWith(AndroidJUnit4.class)
public class LegacyAesCryptoTest {

    private final static String PLAINTEXT = "TestString1234```]]]_ *98//^^^^^";
    private static int CYCLES = 100;

    @Rule
    public final ExpectedException expectedException = ExpectedException.none();

    @BeforeClass
    public static void enableLogging() {
        Logging.create(true);
    }

    @Test
    public void generateFreshKey() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto rsa = getRsaCrypto(context);
        final Crypto aes = getAesCrypto(context, rsa, false);

        // delete any existing keys
        if (aes.doesKeyExist())
            aes.deleteKey();
        assertEquals("Old key should not exist", false, aes.doesKeyExist());

        // generate keys
        aes.generateKey();

        // make sure keys exist
        assertEquals("New key should exist", true, aes.doesKeyExist());
    }

    @Test
    public void encryptAndDecryptBytes() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto rsa = getRsaCrypto(context);
        final Crypto aes = getAesCrypto(context, rsa, false);

        // make sure keys exist
        if (!aes.doesKeyExist())
            aes.generateKey();
        assertEquals("Key should exist", true, aes.doesKeyExist());

        final byte[] plaintextBytes = PLAINTEXT.getBytes();

        // encrypt and decrypt
        final byte[] encryptedBytes = aes.encrypt(plaintextBytes);
        final byte[] decryptedBytes = aes.decrypt(encryptedBytes);

        // check if output is same as input
        assertArrayEquals("Original and encrypted-decrypted output should be equal", plaintextBytes, decryptedBytes);
    }

    @Test
    public void encryptAndDecryptBytesBatch() throws CryptoException {
        final List<byte[]> plaintextBytesList = new ArrayList<>(CYCLES);
        for (int i = 0; i < CYCLES; i++)
            plaintextBytesList.add(PLAINTEXT.getBytes());
        final byte[][] plaintextBytesBatch = plaintextBytesList.toArray(new byte[plaintextBytesList.size()][]);

        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto rsa = getRsaCrypto(context);
        final Crypto aes = getAesCrypto(context, rsa, false);

        // make sure keys exist
        if (!aes.doesKeyExist())
            aes.generateKey();
        assertEquals("Key should exist", true, aes.doesKeyExist());

        // encrypt and decrypt
        final byte[][] encryptedBytesBatch = aes.encrypt(plaintextBytesBatch);
        final byte[][] decryptedBytesBatch = aes.decrypt(encryptedBytesBatch);

        // check if output is same as input
        for (int i = 0; i < plaintextBytesBatch.length; i++)
            assertArrayEquals("Original and encrypted-decrypted output should be equal (index " + i + ")", plaintextBytesBatch[i], decryptedBytesBatch[i]);
    }

    @Test
    public void encryptAndDecryptString() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto rsa = getRsaCrypto(context);
        final Crypto aes = getAesCrypto(context, rsa, false);

        // make sure keys exist
        if (!aes.doesKeyExist())
            aes.generateKey();
        assertEquals("Key should exist", true, aes.doesKeyExist());

        // encrypt and decrypt
        final String encrypted = aes.encrypt(PLAINTEXT);
        final String decrypted = aes.decrypt(encrypted);

        // check if output is same as input
        assertEquals("Original and encrypted-decrypted output should be equal", PLAINTEXT, decrypted);
    }

    @Test
    public void encryptAndDecryptStringBatch() throws CryptoException {
        final Set<String> plaintextStringsSet = new HashSet<>(CYCLES);
        for (int i = 0; i < CYCLES; i++)
            plaintextStringsSet.add(PLAINTEXT);

        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto rsa = getRsaCrypto(context);
        final Crypto aes = getAesCrypto(context, rsa, false);

        // make sure keys exist
        if (!aes.doesKeyExist())
            aes.generateKey();
        assertEquals("Key should exist", true, aes.doesKeyExist());

        // encrypt and decrypt
        final Set<String> encryptedBatch = aes.encrypt(plaintextStringsSet);
        final Set<String> decryptedBatch = aes.decrypt(encryptedBatch);

        // check if output is same as input
        assertEquals("Original and encrypted-decrypted output should be equal", plaintextStringsSet, decryptedBatch);
    }

    // ensure correct behaviour across choice of key retrieval
    @Test
    public void testKeyInMemoryVsKeyOnDemand() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto rsa = getRsaCrypto(context);

        final Crypto aes1 = getAesCrypto(context, rsa, false);

        // make sure keys exist
        if (!aes1.doesKeyExist())
            aes1.generateKey();
        assertEquals("Key should exist", true, aes1.doesKeyExist());

        // encrypt and decrypt
        final String encrypted1 = aes1.encrypt(PLAINTEXT);
        final String encrypted2 = aes1.encrypt(PLAINTEXT + PLAINTEXT);

        final Crypto aes2 = getAesCrypto(context, rsa, true);

        assertEquals("Key should exist", true, aes2.doesKeyExist());

        // encrypt and decrypt
        final String decrypted1 = aes2.decrypt(encrypted1);
        final String decrypted2 = aes2.decrypt(encrypted2);

        // check if output is same as input
        assertEquals("Original and encrypted-decrypted output should be equal", PLAINTEXT, decrypted1);
        assertEquals("Original and encrypted-decrypted output should be equal", PLAINTEXT + PLAINTEXT, decrypted2);
    }

    // data should not be decryptable if keys are deleted
    // tested with key decrypted on demand
    @Test
    public void deleteKey() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto rsax = getRsaCrypto(context);
        final Crypto aes = getAesCrypto(context, rsax, false);

        // make sure keys exist
        if (!aes.doesKeyExist())
            aes.generateKey();
        assertEquals("Key should exist", true, aes.doesKeyExist());

        final String encrypted = aes.encrypt(PLAINTEXT);

        // delete key
        aes.deleteKey();
        assertEquals("Key should not exist", false, aes.doesKeyExist());

        // try to decrypt
        expectedException.expect(CryptoException.class);
        aes.decrypt(encrypted);
    }

    // data should not be decryptable if keys are changed
    // tested with key kept in memory
    @Test
    public void regenerateKey() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto rsax = getRsaCrypto(context);
        final Crypto aes = getAesCrypto(context, rsax, true);

        // make sure keys exist
        if (!aes.doesKeyExist())
            aes.generateKey();
        assertEquals("Key should exist", true, aes.doesKeyExist());

        final String encrypted = aes.encrypt(PLAINTEXT);

        // delete key
        aes.deleteKey();
        assertEquals("Key should not exist", false, aes.doesKeyExist());

        // generate new key
        aes.generateKey();
        assertEquals("Key should exist", true, aes.doesKeyExist());

        // try to decrypt
        expectedException.expect(CryptoException.class);
        final String decrypted = aes.decrypt(encrypted);
        System.out.println("decrypted = " + decrypted);
    }

    @Test
    public void timingWithKeyOnDemand() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto rsax = getRsaCrypto(context);
        final Crypto aes = getAesCrypto(context, rsax, false);

        System.out.println("Starting LegacyAesCrypto benchmarks with key decrypted on demand");

        timingBackend(aes);
    }

    @Test
    public void timingWithKeyInMemory() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto rsax = getRsaCrypto(context);
        final Crypto aes = getAesCrypto(context, rsax, true);

        System.out.println("Starting LegacyAesCrypto benchmarks with decrypted key held in memory");

        timingBackend(aes);

    }

    private void timingBackend(Crypto aes) throws CryptoException {
        final Set<String> plaintextStringsSet = new HashSet<>(CYCLES);
        for (int i = 0; i < CYCLES; i++)
            plaintextStringsSet.add(PLAINTEXT);

        System.out.println(aes.getKeyStorageLocation() == KeyStorageLocation.SECURE ? "AES is being processed in TEE" : "AES is processed in software");

        long startTime, endTime;
        float average;

        // encrypt
        String encrypted = "";
        startTime = System.currentTimeMillis();
        for (int i = 0; i < CYCLES; i++)
            encrypted = aes.encrypt(PLAINTEXT);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / CYCLES;
        System.out.println("Encryption average time (" + CYCLES + " cycles): " + average);

        // decrypt batch
        startTime = System.currentTimeMillis();
        for (int i = 0; i < CYCLES; i++)
            aes.decrypt(encrypted);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / CYCLES;
        System.out.println("Decryption average time (" + CYCLES + " cycles): " + average);

        // encrypt batch
        startTime = System.currentTimeMillis();
        Set<String> encryptedBatch = aes.encrypt(plaintextStringsSet);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / CYCLES;
        System.out.println("Encryption average time (" + CYCLES + " cycles): batch " + average);

        // decrypt batch
        startTime = System.currentTimeMillis();
        aes.decrypt(encryptedBatch);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / CYCLES;
        System.out.println("Decryption average time (" + CYCLES + " cycles): batch " + average);

        System.out.println("LegacyAesCrypto benchmarks completed");
    }

    // generate new AES key if necessary
    private Crypto getAesCrypto(Context context, Crypto rsa, boolean keyInMemory) throws CryptoException {
        Crypto aes = new LegacyAesCrypto(context, rsa, keyInMemory);
        boolean aesKeyExists;
        try {
            aesKeyExists = aes.doesKeyExist();
        } catch (CryptoException ex) {
            // cannot decrypt AES key
            aesKeyExists = false;
        }

        if (aesKeyExists)
            return aes;
        else {
            aes.generateKey();

            if (aes.doesKeyExist())
                return aes;
            else
                throw new CryptoException("Could not generate AES keys");
        }
    }

    // generate new RSA key if necessary
    // RSA stuff has its own tests
    private Crypto getRsaCrypto(Context context) throws CryptoException {
        Crypto rsa = RsaHelper.getExistingCrypto(context, true);
        if (rsa == null) {
            rsa = RsaHelper.generateCrypto(context, true);

            if (rsa == null)
                throw new CryptoException("Could not generate RSA keys");
        }

        return rsa;
    }

}