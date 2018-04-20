package com.bucketscancompile.encryptedsharedpreferences.crypto;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.util.Base64;

import com.bucketscancompile.encryptedsharedpreferences.utils.Logging;
import com.bucketscancompile.encryptedsharedpreferences.utils.Wipe;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES encryption methods (GCM, no padding). The key is stored in SharedPreferences.
 * Uses {@link SecureRsaCrypto} or {@link InsecureRsaCrypto} to protect the AES key.
 *
 * In the future there will be an AesCrypto class that stores the key in secure storage (only compatible with Android API 23+).
 */
public class LegacyAesCrypto extends Crypto {

    private static final String TAG = "LegacyAesCrypto";

    private static final String PREFS = "ESPXmlKeyStore";
    private static final String KEY_NAME = "ESPAES";
    private static final String ALGORITHM = "AES";
    private static final String ALGORITHM_MODE = "AES/GCM/NoPadding";

    private final SharedPreferences mPrefs;
    private final Crypto mRsaCrypto;
    private final boolean mAllowKeyInMemory;

    private SecretKeySpec mKey;

    /**
     * Requires an RSA {@link Crypto} to store the AES key safely.
     * Use {@link com.bucketscancompile.encryptedsharedpreferences.RsaHelper} to obtain this.
     * @param context Context
     * @param rsaCrypto {@link SecureRsaCrypto} or {@link InsecureRsaCrypto}
     * @param allowKeyInMemory If true, the key is stored in memory (faster but less secure)
     */
    public LegacyAesCrypto(@NonNull Context context, @NonNull Crypto rsaCrypto, boolean allowKeyInMemory) {
        super(context);

        mRsaCrypto = rsaCrypto;
        mPrefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        mAllowKeyInMemory = allowKeyInMemory;
        mKey = null;
    }

    @Override
    public KeyStorageLocation getKeyStorageLocation() {
        return KeyStorageLocation.XML;
    }

    /**
     * Returns true if key exists and is decryptable.
     * Returns false if key is missing.
     * @throws CryptoException On failure to decrypt key
     */
    @Override
    public boolean doesKeyExist() throws CryptoException {
        if (mPrefs.contains(KEY_NAME)) {
            // try decrypting key to detect RSA key changed
            getKey();
            return true;
        }

        return false;
    }

    @Override
    public void generateKey() throws CryptoException {
        Logging.getInstance().d(TAG, "generateKey: Generating key (AES, keystore in preferences)");

        final SecureRandom sr = new SecureRandom();
        final byte[] keyBytes = new byte[32];
        sr.nextBytes(keyBytes);

        final byte[] encryptedKeyBytes = mRsaCrypto.encrypt(keyBytes);

        Wipe.bytes(keyBytes);

        final String encryptedKey = Base64.encodeToString(encryptedKeyBytes, Base64.NO_WRAP);
        saveEncryptedKey(encryptedKey);
    }

    @Override
    public void deleteKey() throws CryptoException {
        mKey = null;

        final SharedPreferences.Editor editor = mPrefs.edit();
        editor.remove(KEY_NAME);
        editor.commit();
    }

    @Override
    public byte[][] encrypt(byte[][] plaintextArray) throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot find key for encryption (AES, keystore in preferences)");

        final byte[][] ciphertextArray = new byte[plaintextArray.length][];
        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM_MODE);
            final SecretKeySpec key = getKey();

            byte[] iv;
            IvParameterSpec parameterSpec;
            ByteArrayOutputStream bos;
            CipherOutputStream cos;
            ByteBuffer byteBuffer;
            for (int i = 0; i < plaintextArray.length; i++) {
                iv = generateIV();

                parameterSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

                // stream to handle large data
                bos = new ByteArrayOutputStream();
                cos = new CipherOutputStream(bos, cipher);
                cos.write(plaintextArray[i]);
                cos.close();

                // combine IV and ciphertext
                byteBuffer = ByteBuffer.allocate(4 + iv.length + bos.size());
                byteBuffer.putInt(iv.length);
                byteBuffer.put(iv);
                byteBuffer.put(bos.toByteArray());

                ciphertextArray[i] = byteBuffer.array();
            }

            return ciphertextArray;

        } catch (Exception ex) {
            throw new CryptoException("Encryption failed (AES, keystore in preferences)", ex);
        }
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot find key for encryption (AES, keystore in preferences)");

        final byte[] iv = generateIV();

        final byte[] ciphertext;
        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM_MODE);
            final IvParameterSpec parameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, getKey(), parameterSpec);

            // stream to handle large data
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            final CipherOutputStream cos = new CipherOutputStream(bos, cipher);
            cos.write(plaintext);
            cos.close();

            ciphertext = bos.toByteArray();

        } catch (Exception ex) {
            throw new CryptoException("Encryption failed (AES, keystore in preferences)", ex);
        }

        // combine IV and ciphertext
        final ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + ciphertext.length);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(ciphertext);

        return byteBuffer.array();
    }

    @Override
    public byte[][] decrypt(byte[][] ciphertextArray) throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot find key for decryption (AES, keystore in preferences)");

        final byte[][] plaintextArray = new byte[ciphertextArray.length][];
        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM_MODE);
            final SecretKeySpec key = getKey();

            ByteBuffer ciphertextByteBuffer;
            int ivLength;
            byte[] iv, ciphertext;
            IvParameterSpec parameterSpec;
            ByteArrayInputStream bis;
            CipherInputStream cis;
            ArrayList<Byte> buffer;
            int next;
            for (int i = 0; i < ciphertextArray.length; i++) {
                // extract IV and ciphertext
                ciphertextByteBuffer = ByteBuffer.wrap(ciphertextArray[i]);
                ivLength = ciphertextByteBuffer.getInt();
                iv = new byte[ivLength];
                ciphertextByteBuffer.get(iv);
                ciphertext = new byte[ciphertextByteBuffer.remaining()];
                ciphertextByteBuffer.get(ciphertext);

                parameterSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

                // stream to handle large data
                bis = new ByteArrayInputStream(ciphertext);
                cis = new CipherInputStream(bis, cipher);
                buffer = new ArrayList<>();
                while ((next = cis.read()) != -1)
                    buffer.add((byte)next);

                // buffer may be empty when the key is incorrect
                if (buffer.isEmpty())
                    throw new CryptoException("Cipher output is empty");

                // convert buffer to byte array
                plaintextArray[i] = new byte[buffer.size()];
                for (int j = 0; j < buffer.size(); j++)
                    plaintextArray[i][j] = buffer.get(j);
            }

            return plaintextArray;

        } catch (Exception ex) {
            throw new CryptoException("Decryption failed (AES, keystore in preferences)", ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphertextWithIV) throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot find key for decryption (AES, keystore in preferences)");

        // separate IV and ciphertext
        final ByteBuffer byteBuffer = ByteBuffer.wrap(ciphertextWithIV);
        final int ivLength = byteBuffer.getInt();
        final byte[] iv = new byte[ivLength];
        byteBuffer.get(iv);
        final byte[] ciphertext = new byte[byteBuffer.remaining()];
        byteBuffer.get(ciphertext);

        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM_MODE);
            final IvParameterSpec parameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, getKey(), parameterSpec);

            // stream to handle large data
            final ByteArrayInputStream bis = new ByteArrayInputStream(ciphertext);
            final CipherInputStream cis = new CipherInputStream(bis, cipher);
            final ArrayList<Byte> buffer = new ArrayList<>();
            int next;
            while ((next = cis.read()) != -1)
                buffer.add((byte)next);

            // buffer may be empty when the key is incorrect
            if (buffer.isEmpty())
                throw new CryptoException("Cipher output is empty");

            // convert buffer to byte array
            final byte[] out = new byte[buffer.size()];
            for (int i = 0; i < buffer.size(); i++)
                out[i] = buffer.get(i);

            return out;

        } catch (Exception ex) {
            throw new CryptoException("Decryption failed (AES, keystore in preferences)", ex);
        }
    }

    private byte[] generateIV() {
        final SecureRandom sr = new SecureRandom();
        final byte[] ivBytes = new byte[12];
        sr.nextBytes(ivBytes);
        return ivBytes;
    }

    private SecretKeySpec getKey() throws CryptoException {
        // use key from memory if possible
        if (mAllowKeyInMemory && mKey != null)
            return mKey;

        final String encryptedKey = loadEncryptedKey();
        final byte[] encryptedKeyBytes = Base64.decode(encryptedKey, Base64.NO_WRAP);

        try {
            final byte[] keyBytes = mRsaCrypto.decrypt(encryptedKeyBytes);

            final SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, ALGORITHM);

            // can wipe since SecretKeySpec clones the key
            Wipe.bytes(keyBytes);

            // store key in memory if allowed
            if (mAllowKeyInMemory)
                mKey = secretKeySpec;

            return secretKeySpec;
        } catch (CryptoException ex) {
            throw new CryptoException("AES key could not be decrypted - RSA keys may have changed", ex);
        }
    }

    private String loadEncryptedKey() throws CryptoException {
        final String encryptedKey = mPrefs.getString(KEY_NAME, null);
        if (encryptedKey == null)
            throw new CryptoException("Encrypted key was not found (AES, keystore in preferences)");
        else
            return encryptedKey;
    }

    private void saveEncryptedKey(String encryptedKey) {
        final SharedPreferences.Editor editor = mPrefs.edit();
        editor.putString(KEY_NAME, encryptedKey);
        editor.commit();
    }
}
