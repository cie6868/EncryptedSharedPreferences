package com.bucketscancompile.encryptedsharedpreferences;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.bucketscancompile.encryptedsharedpreferences.crypto.Crypto;
import com.bucketscancompile.encryptedsharedpreferences.crypto.CryptoException;
import com.bucketscancompile.encryptedsharedpreferences.crypto.LegacyAesCrypto;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

@RunWith(AndroidJUnit4.class)
public class KeyHasherTest {

    private final static String PLAINTEXT = "TestString1234```]]]_ *98//^^^^^";
    private final static int CYCLES = 100;

    @Rule
    public final ExpectedException expectedException = ExpectedException.none();

    @Test
    public void generateFreshSalt() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto aes = getAesCrypto(context, false);
        final KeyHasher hasher = new KeyHasher(context, aes);

        // delete any existing salt
        if (hasher.doesSaltExist())
            hasher.deleteSalt();
        assertEquals("Old salt should not exist", false, hasher.doesSaltExist());

        // generate salt
        hasher.generateSalt();

        // make sure salt exists
        assertEquals("New salt should exist", true, hasher.doesSaltExist());
    }

    @Test
    public void hashSHA512BatchTwice() throws CryptoException {
        final List<String> plaintextList = new ArrayList<>(CYCLES);
        for (int i = 0; i < CYCLES; i++)
            plaintextList.add(PLAINTEXT);
        final String[] plaintextArray = plaintextList.toArray(new String[plaintextList.size()]);

        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto aes = getAesCrypto(context, false);
        final KeyHasher hasher = new KeyHasher(context, aes);

        // make sure salt exists
        if (!hasher.doesSaltExist())
            hasher.generateSalt();
        assertEquals("Key should exist", true, hasher.doesSaltExist());

        // hash
        final String[] hash1 = hasher.hashBatchSHA512(plaintextArray);

        // another hash
        final String[] hash2 = hasher.hashBatchSHA512(plaintextArray);

        assertArrayEquals("Both hashes have the same salt and must be equal", hash1, hash2);
    }

    @Test
    public void hashSHA512Twice() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto aes = getAesCrypto(context, false);
        final KeyHasher hasher = new KeyHasher(context, aes);

        // make sure salt exists
        if (!hasher.doesSaltExist())
            hasher.generateSalt();
        assertEquals("Key should exist", true, hasher.doesSaltExist());

        // hash
        final String hash1 = hasher.hashSHA512(PLAINTEXT);

        // another hash
        final String hash2 = hasher.hashSHA512(PLAINTEXT);

        // equate
        assertEquals("Both hashes have the same salt and must be equal", hash1, hash2);
    }

    @Test
    public void hashJavaPBKDFTwice() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto aes = getAesCrypto(context, false);
        final KeyHasher hasher = new KeyHasher(context, aes);

        // make sure salt exists
        if (!hasher.doesSaltExist())
            hasher.generateSalt();
        assertEquals("Key should exist", true, hasher.doesSaltExist());

        // hash
        final String hash1 = hasher.hashJavaPBKDF(PLAINTEXT);

        // another hash
        final String hash2 = hasher.hashJavaPBKDF(PLAINTEXT);

        // equate
        assertEquals("Both hashes have the same salt and must be equal", hash1, hash2);
    }

    @Test
    public void hashJavaPBKDFBatchTwice() throws CryptoException {
        final List<String> plaintextList = new ArrayList<>(CYCLES);
        for (int i = 0; i < CYCLES; i++)
            plaintextList.add(PLAINTEXT);
        final String[] plaintextArray = plaintextList.toArray(new String[plaintextList.size()]);

        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto aes = getAesCrypto(context, false);
        final KeyHasher hasher = new KeyHasher(context, aes);

        // make sure salt exists
        if (!hasher.doesSaltExist())
            hasher.generateSalt();
        assertEquals("Key should exist", true, hasher.doesSaltExist());

        // hash
        final String[] hash1 = hasher.hashBatchJavaPBKDF(plaintextArray);

        // another hash
        final String[] hash2 = hasher.hashBatchJavaPBKDF(plaintextArray);

        assertArrayEquals("Both hashes have the same salt and must be equal", hash1, hash2);
    }

    // confirm hash output is constant for the same input
    @Test
    public void hashSpongyPBKDFTwice() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto aes = getAesCrypto(context, false);
        final KeyHasher hasher = new KeyHasher(context, aes);

        // make sure salt exists
        if (!hasher.doesSaltExist())
            hasher.generateSalt();
        assertEquals("Key should exist", true, hasher.doesSaltExist());

        // hash
        final String hash1 = hasher.hashSpongyPBKDF(PLAINTEXT);

        // another hash
        final String hash2 = hasher.hashSpongyPBKDF(PLAINTEXT);

        // equate
        assertEquals("Both hashes have the same salt and must be equal", hash1, hash2);
    }

    @Test
    public void hashSpongyPBKDFBatchTwice() throws CryptoException {
        final List<String> plaintextList = new ArrayList<>(CYCLES);
        for (int i = 0; i < CYCLES; i++)
            plaintextList.add(PLAINTEXT);
        final String[] plaintextArray = plaintextList.toArray(new String[plaintextList.size()]);

        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto aes = getAesCrypto(context, false);
        final KeyHasher hasher = new KeyHasher(context, aes);

        // make sure salt exists
        if (!hasher.doesSaltExist())
            hasher.generateSalt();
        assertEquals("Key should exist", true, hasher.doesSaltExist());

        // hash
        final String[] hash1 = hasher.hashBatchSpongyPBKDF(plaintextArray);

        // another hash
        final String[] hash2 = hasher.hashBatchSpongyPBKDF(plaintextArray);

        // equate
        assertArrayEquals("Both hashes have the same salt and must be equal", hash1, hash2);
    }

    // data should not be hashed if salt is deleted
    @Test
    public void deleteHash() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto aesx = getAesCrypto(context, false);
        final KeyHasher hasher = new KeyHasher(context, aesx);

        // make sure salt exists
        if (!hasher.doesSaltExist())
            hasher.generateSalt();
        assertEquals("Key should exist", true, hasher.doesSaltExist());

        // delete salt
        hasher.deleteSalt();

        // try to decrypt
        expectedException.expect(CryptoException.class);
        hasher.hash(PLAINTEXT);
    }

    // data hashed with different salts should not be equal
    @Test
    public void regenerateKey() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto aesx = getAesCrypto(context, false);
        final KeyHasher hasher = new KeyHasher(context, aesx);

        // make sure salt exists
        if (!hasher.doesSaltExist())
            hasher.generateSalt();
        assertEquals("Key should exist", true, hasher.doesSaltExist());

        final String hash1 = hasher.hash(PLAINTEXT);

        // regenerate salt
        hasher.deleteSalt();
        hasher.generateSalt();

        final String hash2 = hasher.hash(PLAINTEXT);

        // try to decrypt
        assertNotEquals("Hashes should be different", hash1, hash2);
    }

    @Test
    public void timingWithKeyOnDemand() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto aes = getAesCrypto(context, false);
        final KeyHasher hasher = new KeyHasher(context, aes);

        System.out.println("Starting hash benchmarks with AES key decrypted on demand");

        timingBackend(hasher);
    }

    @Test
    public void timingWithKeyInMemory() throws CryptoException {
        final Context context = InstrumentationRegistry.getTargetContext();
        final Crypto aes = getAesCrypto(context, true);
        final KeyHasher hasher = new KeyHasher(context, aes);

        System.out.println("Starting hash benchmarks with decrypted AES key in memory");

        timingBackend(hasher);
    }

    private void timingBackend(KeyHasher hasher) throws CryptoException {
        final List<String> plaintextList = new ArrayList<>(CYCLES);
        for (int i = 0; i < CYCLES; i++)
            plaintextList.add(PLAINTEXT);
        final String[] plaintextArray = plaintextList.toArray(new String[plaintextList.size()]);

        long startTime, endTime;
        float average;

        // SHA512 MessageDigest
        startTime = System.currentTimeMillis();
        for (int i = 0; i < CYCLES; i++)
            hasher.hashSHA512(PLAINTEXT);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / CYCLES;
        System.out.println("Hashing average (" + CYCLES + " cycles): SHA512 MessageDigest " + average);

        // SHA512 MessageDigest batch mode
        startTime = System.currentTimeMillis();
        hasher.hashBatchSHA512(plaintextArray);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / CYCLES;
        System.out.println("Hashing average (" + CYCLES + " cycles): SHA512 MessageDigest batch " + average);

        // PBKDF2 SecretKeyFactory
        startTime = System.currentTimeMillis();
        for (int i = 0; i < CYCLES; i++)
            hasher.hashJavaPBKDF(PLAINTEXT);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / CYCLES;
        System.out.println("Hashing average (" + CYCLES + " cycles): PBKDF2 SecretKeyFactory " + average);

        // PBKDF2 SecretKeyFactory batch
        startTime = System.currentTimeMillis();
        hasher.hashBatchJavaPBKDF(plaintextArray);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / CYCLES;
        System.out.println("Hashing average (" + CYCLES + " cycles): PBKDF2 SecretKeyFactory batch " + average);

        // PBKDF2 SpongyCastle
        startTime = System.currentTimeMillis();
        for (int i = 0; i < CYCLES; i++)
            hasher.hashSpongyPBKDF(PLAINTEXT);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / CYCLES;
        System.out.println("Hashing average (" + CYCLES + " cycles): PBKDF2 SpongyCastle " + average);

        // PBKDF2 SpongyCastle batch
        startTime = System.currentTimeMillis();
        hasher.hashBatchSpongyPBKDF(plaintextArray);
        endTime = System.currentTimeMillis();
        average = (float)(endTime - startTime) / CYCLES;
        System.out.println("Hashing average (" + CYCLES + " cycles): PBKDF2 SpongyCastle batch " + average);

        System.out.println("Hash benchmarks completed");
    }

    // RSA stuff has its own tests
    private Crypto getAesCrypto(Context context, boolean keyInMemory) throws CryptoException {
        Crypto rsa = RsaHelper.getExistingCrypto(context, true);
        if (rsa == null)
            rsa = RsaHelper.generateCrypto(context, true);

        return new LegacyAesCrypto(context, rsa, keyInMemory);
    }

}