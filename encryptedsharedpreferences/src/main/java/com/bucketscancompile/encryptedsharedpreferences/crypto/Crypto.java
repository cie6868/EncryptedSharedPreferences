package com.bucketscancompile.encryptedsharedpreferences.crypto;

import android.content.Context;
import android.util.Base64;

import java.util.LinkedHashSet;
import java.util.Set;

public abstract class Crypto {

    protected Context mContext;

    protected Crypto(Context context) {
        mContext = context;
    }

    public abstract KeyStorageLocation getKeyStorageLocation();

    public abstract boolean doesKeyExist() throws CryptoException;

    public abstract void generateKey() throws CryptoException;

    public abstract void deleteKey() throws CryptoException;

    /**
     * Convenience method for encryption that incorporates base64 encoding (no-wrap).
     * @param plaintextSet Set of strings to be encrypted
     * @return Set of base64-encoded encrypted strings
     * @throws CryptoException On encrpytion failure
     */
    public final Set<String> encrypt(Set<String> plaintextSet) throws CryptoException {
        final Set<byte[]> plaintextBytesSet = new LinkedHashSet<>(plaintextSet.size());
        for (String plaintext : plaintextSet)
            plaintextBytesSet.add(plaintext.getBytes());

        final byte[][] ciphertextBytesArray = encrypt(plaintextBytesSet.toArray(new byte[plaintextBytesSet.size()][]));

        final Set<String> ciphertextSet = new LinkedHashSet<>(ciphertextBytesArray.length);
        for (byte[] ciphertextBytes : ciphertextBytesArray)
            ciphertextSet.add(Base64.encodeToString(ciphertextBytes, Base64.NO_WRAP));
        return ciphertextSet;
    }

    /**
     * Convenience method for encryption that incorporates base64 encoding (no-wrap).
     * @param plaintext String to be encrypted
     * @return Base64-encoded encrypted string
     * @throws CryptoException On encrpytion failure
     */
    public final String encrypt(String plaintext) throws CryptoException {
        final byte[] plaintextBytes = plaintext.getBytes();
        final byte[] ciphertextBytes = encrypt(plaintextBytes);
        return Base64.encodeToString(ciphertextBytes, Base64.NO_WRAP);
    }

    public abstract byte[][] encrypt(byte[][] plaintextArray) throws CryptoException;

    public abstract byte[] encrypt(byte[] plaintext) throws CryptoException;

    /**
     * Convenience method for encryption that incorporates base64 encoding (no-wrap).
     * @param ciphertextSet Set of base64-encoded encrypted strings
     * @return List of plaintext strings
     * @throws CryptoException On decryption failure
     */
    public final Set<String> decrypt(Set<String> ciphertextSet) throws CryptoException {
        final Set<byte[]> ciphertextBytesSet = new LinkedHashSet<>(ciphertextSet.size());
        for (String ciphertext: ciphertextSet)
            ciphertextBytesSet.add(Base64.decode(ciphertext, Base64.NO_WRAP));

        final byte[][] plaintextBytesArray = decrypt(ciphertextBytesSet.toArray(new byte[ciphertextBytesSet.size()][]));

        final Set<String> plaintextSet = new LinkedHashSet<>(plaintextBytesArray.length);
        for (byte[] plaintextBytes : plaintextBytesArray)
            plaintextSet.add(new String(plaintextBytes));
        return plaintextSet;
    }

    /**
     * Convenience method for decryption that incorporates Base64 decoding (no-wrap).
     * @param ciphertext Base64-encoded encrypted string
     * @return Plaintext string
     * @throws CryptoException On decryption failure
     */
    public final String decrypt(String ciphertext) throws CryptoException {
        final byte[] ciphertextBytes = Base64.decode(ciphertext, Base64.NO_WRAP);
        final byte[] plaintextBytes =  decrypt(ciphertextBytes);
        return new String(plaintextBytes);
    }

    public abstract byte[][] decrypt(byte[][] ciphertextArray) throws CryptoException;

    public abstract byte[] decrypt(byte[] ciphertext) throws CryptoException;

}
