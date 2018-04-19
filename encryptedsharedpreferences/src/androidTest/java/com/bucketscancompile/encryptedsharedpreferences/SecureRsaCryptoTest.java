package com.bucketscancompile.encryptedsharedpreferences;

import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.bucketscancompile.encryptedsharedpreferences.crypto.Crypto;
import com.bucketscancompile.encryptedsharedpreferences.crypto.CryptoException;
import com.bucketscancompile.encryptedsharedpreferences.crypto.SecureRsaCrypto;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@RunWith(AndroidJUnit4.class)
public class SecureRsaCryptoTest {

    private static final String PLAINTEXT = "TestString1234```]]]_ *98//^^^^^";

    @Rule
    public final ExpectedException expectedException = ExpectedException.none();

    @Test
    public void generateFreshKey() throws CryptoException {
        final Crypto rsa = new SecureRsaCrypto(InstrumentationRegistry.getTargetContext());

        // delete any existing keys
        if (rsa.doesKeyExist())
            rsa.deleteKey();
        assertEquals("Old key should not exist", false, rsa.doesKeyExist());

        // generate keys
        rsa.generateKey();

        // make sure keys exist
        assertEquals("New key should exist", true, rsa.doesKeyExist());
    }

    @Test
    public void encryptAndDecryptBytes() throws CryptoException {
        final Crypto rsa = new SecureRsaCrypto(InstrumentationRegistry.getTargetContext());

        // make sure keys exist
        if (!rsa.doesKeyExist())
            rsa.generateKey();
        assertEquals("Key should exist", true, rsa.doesKeyExist());

        final byte[] plaintextBytes = PLAINTEXT.getBytes();

        // encrypt and decrypt
        final byte[] encryptedBytes = rsa.encrypt(plaintextBytes);
        final byte[] decryptedBytes = rsa.decrypt(encryptedBytes);

        // check if output is same as input
        assertArrayEquals("Original and encrypted-decrypted output should be equal", decryptedBytes, plaintextBytes);
    }

    @Test
    public void encryptAndDecryptStrings() throws CryptoException {
        final Crypto rsa = new SecureRsaCrypto(InstrumentationRegistry.getTargetContext());

        // make sure keys exist
        if (!rsa.doesKeyExist())
            rsa.generateKey();
        assertEquals("Key should exist", true, rsa.doesKeyExist());

        // encrypt and decrypt
        final String encrypted = rsa.encrypt(PLAINTEXT);
        final String decrypted = rsa.decrypt(encrypted);

        // check if output is same as input
        assertEquals("Original and encrypted-decrypted output should be equal", decrypted, PLAINTEXT);
    }

    // data should not be decryptable if keys are deleted
    @Test
    public void deleteKeys() throws CryptoException {
        final Crypto rsa = new SecureRsaCrypto(InstrumentationRegistry.getTargetContext());

        // make sure keys exist
        if (!rsa.doesKeyExist())
            rsa.generateKey();
        assertEquals("Key should exist", true, rsa.doesKeyExist());

        final String encrypted = rsa.encrypt(PLAINTEXT);

        // delete key
        rsa.deleteKey();
        assertEquals("Key should not exist", false, rsa.doesKeyExist());

        // try to decrypt
        expectedException.expect(CryptoException.class);
        rsa.decrypt(encrypted);
    }

    // data should not be decryptable if keys are changed
    @Test
    public void regenerateKeys() throws CryptoException {
        final Crypto rsa = new SecureRsaCrypto(InstrumentationRegistry.getTargetContext());

        // make sure keys exist
        if (!rsa.doesKeyExist())
            rsa.generateKey();
        assertEquals("Key should exist", true, rsa.doesKeyExist());

        final String encrypted = rsa.encrypt(PLAINTEXT);

        // delete key
        rsa.deleteKey();
        assertEquals("Key should not exist", false, rsa.doesKeyExist());

        // generate new key
        rsa.generateKey();
        assertEquals("Key should exist", true, rsa.doesKeyExist());

        // try to decrypt
        expectedException.expect(CryptoException.class);
        final String decrypted = rsa.decrypt(encrypted);
        System.out.println("decrypted = " + decrypted);
    }

}