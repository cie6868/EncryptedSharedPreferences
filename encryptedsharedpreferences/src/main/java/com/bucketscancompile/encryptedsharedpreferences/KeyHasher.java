package com.bucketscancompile.encryptedsharedpreferences;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.util.Base64;

import com.bucketscancompile.encryptedsharedpreferences.crypto.Crypto;
import com.bucketscancompile.encryptedsharedpreferences.crypto.CryptoException;
import com.bucketscancompile.encryptedsharedpreferences.utils.Wipe;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/*import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;*/

/**
 * Methods to hash keys in key-value pairs.
 * Hashing is done using a fixed salt. The salt is stored encrypted with AES.
 * SHA512 is used in the interest of performance. PBKDF2 is more secure but seems to perform poorly on mid-range devices.
 */
class KeyHasher {

    private static final String TAG = "KeyHasher";

    private static final String PREFS = "ESPXmlKeyStore";
    private static final String KEY_NAME = "ESPPBKDF";
    private static final String ALGORITHM_SHA512 = "SHA512";
    private static final String ALGORITHM_PBKDF2 = "PBKDF2WithHmacSHA1";

    // chosen to balance speed and brute-forcability
    private static final int PBKDF2_ITERATION_COUNT = 10000;

    private final SharedPreferences mPrefs;
    private final Crypto mAesCrypto;

    /**
     * Must be provided a {@link Crypto} to encrypt and decrypt the salt. Preferably AES.
     * @param context Context
     * @param aesCrypto {@link Crypto} object
     */
    KeyHasher(@NonNull Context context, @NonNull Crypto aesCrypto) {
        mPrefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        mAesCrypto = aesCrypto;
    }

    /**
     * Returns true if salt exists and is decryptable.
     * Return false if salt is missing.
     * @throws CryptoException On failure to decrypt salt
     */
    boolean doesSaltExist() throws CryptoException {
        if (mPrefs.contains(KEY_NAME)) {
            try {
                final String encryptedSaltString = mPrefs.getString(KEY_NAME, null);
                if (encryptedSaltString == null)
                    throw new CryptoException("Salt is empty");

                final byte[] encryptedSalt = Base64.decode(encryptedSaltString, Base64.NO_WRAP);
                final byte[] saltBytes = mAesCrypto.decrypt(encryptedSalt);
                Wipe.bytes(saltBytes);

                return true;
            } catch (Exception ex) {
                throw new CryptoException("Failed to decrypt salt", ex);
            }
        }

        return false;
    }

    void generateSalt() throws CryptoException {
        final byte[] salt = new byte[16];

        final SecureRandom sr = new SecureRandom();
        sr.nextBytes(salt);

        final byte[] encryptedSalt = mAesCrypto.encrypt(salt);

        Wipe.bytes(salt);

        final String encryptedSaltString = Base64.encodeToString(encryptedSalt, Base64.NO_WRAP);

        final SharedPreferences.Editor editor = mPrefs.edit();
        editor.putString(KEY_NAME, encryptedSaltString);
        editor.commit();
    }

    void deleteSalt() {
        final SharedPreferences.Editor editor = mPrefs.edit();
        editor.remove(KEY_NAME);
        editor.commit();
    }

    /**
     * Hash using the default hashing algorithm.
     * @param dataSet Set of input strings
     * @return Set of hashed, base64-encoded output strings
     * @throws CryptoException On failure to decrypt salt or missing hashing algorithm
     */
    Set<String> hashBatch(Set<String> dataSet) throws CryptoException {
        // current default is PBKDF SpongyCastle implementation
        final String[] dataArray = dataSet.toArray(new String[dataSet.size()]);
        final String[] hashedDataArray = hashBatch(dataArray);
        final Set<String> hashedDataSet = new LinkedHashSet<>(hashedDataArray.length);
        hashedDataSet.addAll(Arrays.asList(hashedDataArray));
        return hashedDataSet;
    }

    /**
     * Hash using the default hashing algorithm.
     * @param dataArray Array of input strings
     * @return Array of hashed, base64-encoded output strings
     * @throws CryptoException On failure to decrypt salt or missing hashing algorithm
     */
    String[] hashBatch(String[] dataArray) throws CryptoException {
        return hashBatchSHA512(dataArray);
    }

    /**
     * Hash using the default hashing algorithm.
     * @param data Input string
     * @return Hashed, base64-encoded output string
     * @throws CryptoException On failure to decrypt salt or missing hashing algorithm
     */
    String hash(String data) throws CryptoException {
        return hashSHA512(data);
    }

    /**
     * Hash with SHA512 using Java's {@link MessageDigest}.
     * @param dataArray Array of input strings
     * @return Array of hashed, base64-encoded output strings
     * @throws CryptoException On failure to decrypt salt
     */
    String[] hashBatchSHA512(String[] dataArray) throws CryptoException {
        final String encryptedSaltString = mPrefs.getString(KEY_NAME, null);
        if (encryptedSaltString == null)
            throw new CryptoException("Cannot find salt for hashing");

        final byte[] encryptedSalt = Base64.decode(encryptedSaltString, Base64.NO_WRAP);

        final String[] hashArray = new String[dataArray.length];
        byte[] saltBytes = null;
        byte[] allBytes = null;
        try {
            saltBytes = mAesCrypto.decrypt(encryptedSalt);

            MessageDigest messageDigest;
            for (int i = 0; i < dataArray.length; i++) {

                allBytes = com.bucketscancompile.encryptedsharedpreferences.utils.Arrays.concatenate(saltBytes, dataArray[i].getBytes());

                messageDigest = MessageDigest.getInstance(ALGORITHM_SHA512);
                messageDigest.update(allBytes);

                Wipe.bytes(allBytes);

                hashArray[i] = Base64.encodeToString(messageDigest.digest(), Base64.NO_WRAP);
            }

            Wipe.bytes(saltBytes);

            return hashArray;

        } catch (CryptoException ex) {
            throw new CryptoException("Failed to decrypt salt - AES or RSA keys may have changed");
        } catch (Exception ex) {
            Wipe.bytes(saltBytes);
            Wipe.bytes(allBytes);
            throw new CryptoException("Failed to hash the given string (SHA512)", ex);
        }
    }

    /**
     * Hash with SHA512 using Java's {@link MessageDigest}.
     * @param data Input string
     * @return Hashed, base64-encoded output string
     * @throws CryptoException On failure to decrypt salt
     */
    String hashSHA512(String data) throws CryptoException {
        final String encryptedSaltString = mPrefs.getString(KEY_NAME, null);
        if (encryptedSaltString == null)
            throw new CryptoException("Cannot find salt for hashing");

        final byte[] encryptedSalt = Base64.decode(encryptedSaltString, Base64.NO_WRAP);

        try {
            final byte[] saltBytes = mAesCrypto.decrypt(encryptedSalt);

            final byte[] allBytes = com.bucketscancompile.encryptedsharedpreferences.utils.Arrays.concatenate(saltBytes, data.getBytes());

            Wipe.bytes(saltBytes);

            final MessageDigest md = MessageDigest.getInstance(ALGORITHM_SHA512);
            md.update(allBytes);

            Wipe.bytes(allBytes);

            return Base64.encodeToString(md.digest(), Base64.NO_WRAP);

        } catch (CryptoException ex) {
            throw new CryptoException("Failed to decrypt salt - AES or RSA keys may have changed");
        }  catch (Exception ex) {
            throw new CryptoException("Failed to hash the given string (SHA512)", ex);
        }
    }

    /**
     * Hash using PBKDF2 with Java library.
     * @param dataArray Array of input strings
     * @return Array of hashed, base64-encoded output strings
     * @throws CryptoException On failure to decrypt salt or missing hashing algorithm
     */
    String[] hashBatchJavaPBKDF(String[] dataArray) throws CryptoException {
        final String encryptedSaltString = mPrefs.getString(KEY_NAME, null);
        if (encryptedSaltString == null)
            throw new CryptoException("Cannot find salt for hashing");

        final byte[] encryptedSalt = Base64.decode(encryptedSaltString, Base64.NO_WRAP);
        final byte[] salt = mAesCrypto.decrypt(encryptedSalt);

        final String[] hashArray = new String[dataArray.length];
        try {
            final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM_PBKDF2);

            KeySpec keySpec;
            byte[] hashBytes;
            for (int i = 0; i < dataArray.length; i++) {
                keySpec = new PBEKeySpec(dataArray[i].toCharArray(), salt, PBKDF2_ITERATION_COUNT, 128);
                hashBytes = secretKeyFactory.generateSecret(keySpec).getEncoded();

                hashArray[i] = Base64.encodeToString(hashBytes, Base64.NO_WRAP);
            }

            Wipe.bytes(salt);

            return hashArray;

        } catch (Exception ex) {
            Wipe.bytes(salt);
            throw new CryptoException("Failed to hash the given string (PBKDF2 Java)", ex);
        }
    }

    /**
     * Hash using PBKDF2 with Java library.
     * @param data Input string
     * @return Hashed, base64-encoded output string
     * @throws CryptoException On failure to decrypt salt or missing hashing algorithm
     */
    String hashJavaPBKDF(String data) throws CryptoException {
        final String encryptedSaltString = mPrefs.getString(KEY_NAME, null);
        if (encryptedSaltString == null)
            throw new CryptoException("Cannot find salt for hashing");

        final byte[] encryptedSalt = Base64.decode(encryptedSaltString, Base64.NO_WRAP);
        final byte[] salt = mAesCrypto.decrypt(encryptedSalt);

        final KeySpec keySpec = new PBEKeySpec(data.toCharArray(), salt, PBKDF2_ITERATION_COUNT, 128);

        Wipe.bytes(salt);

        try {
            final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM_PBKDF2);
            final byte[] hashBytes = secretKeyFactory.generateSecret(keySpec).getEncoded();

            return Base64.encodeToString(hashBytes, Base64.NO_WRAP);
        } catch (Exception ex) {
            throw new CryptoException("Failed to hash the given string (PBKDF2 Java)", ex);
        }
    }

    /**
     * Hash using PBKDF2 with SpongyCastle.
     * @param dataArray Array of input strings
     * @return Array of hashed, base64-encoded output strings
     * @throws CryptoException On failure to decrypt salt
     */
    String[] hashBatchSpongyPBKDF(String[] dataArray) throws CryptoException {
        throw new UnsupportedOperationException("SpongyCastle has not been imported");

        /*final String encryptedSaltString = mPrefs.getString(KEY_NAME, null);
        if (encryptedSaltString == null)
            throw new CryptoException("Cannot find salt for hashing");

        final byte[] encryptedSalt = Base64.decode(encryptedSaltString, Base64.NO_WRAP);
        final byte[] saltBytes = mAesCrypto.decrypt(encryptedSalt);

        final PBEParametersGenerator generator= new PKCS5S2ParametersGenerator();

        final String[] hashArray = new String[dataArray.length];
        byte[] dataBytes;
        KeyParameter keyParameter;
        for (int i = 0; i < dataArray.length; i++) {
            dataBytes = PBEParametersGenerator.PKCS5PasswordToBytes(dataArray[i].toCharArray());
            generator.init(dataBytes, saltBytes, PBKDF2_ITERATION_COUNT);
            keyParameter = (KeyParameter)generator.generateDerivedParameters(128);

            hashArray[i] = Base64.encodeToString(keyParameter.getKey(), Base64.NO_WRAP);
        }

        Wipe.bytes(saltBytes);

        return hashArray;*/
    }

    /**
     * Hash using PBKDF2 with SpongyCastle.
     * @param data Input string
     * @return Hashed, base64-encoded output string
     * @throws CryptoException On failure to decrypt salt
     */
    String hashSpongyPBKDF(String data) throws CryptoException {
        throw new UnsupportedOperationException("SpongyCastle has not been imported");
        /*final String encryptedSaltString = mPrefs.getString(KEY_NAME, null);
        if (encryptedSaltString == null)
            throw new CryptoException("Cannot find salt for hashing");

        final byte[] encryptedSalt = Base64.decode(encryptedSaltString, Base64.NO_WRAP);

        final PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
        final byte[] dataBytes = PBEParametersGenerator.PKCS5PasswordToBytes(data.toCharArray());

        final byte[] saltBytes = mAesCrypto.decrypt(encryptedSalt);

        generator.init(dataBytes, saltBytes, PBKDF2_ITERATION_COUNT);

        final KeyParameter keyParameter = (KeyParameter)generator.generateDerivedParameters(128);

        // causes bugs if salt is wiped before generator.generateDerivedParameters()
        Wipe.bytes(saltBytes);

        final String out = Base64.encodeToString(keyParameter.getKey(), Base64.NO_WRAP);

        return out;*/
    }

}
