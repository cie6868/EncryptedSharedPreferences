package com.bucketscancompile.encryptedsharedpreferences.crypto;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;

import com.bucketscancompile.encryptedsharedpreferences.utils.Logging;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import static java.security.spec.RSAKeyGenParameterSpec.F4;

/**
 * RSA encryption within the Trusted Excecution Environment (TEE).
 * Plaintexts must be under 256 bytes.
 */
public class SecureRsaCrypto extends Crypto {

    private static final String TAG = "SecureRsaCrypto";

    private static final String KEYSTORE_NAME = "AndroidKeyStore";
    private static final String KEY_NAME = "ESPRSA";
    private static final String ALGORITHM = "RSA";
    private static final String ALGORITHM_MODE = "RSA/ECB/PKCS1Padding";

    private final KeyStore mKeyStore;

    public SecureRsaCrypto(Context context) throws CryptoException {
        super(context);

        mKeyStore = initKeyStore();
    }

    @Override
    public KeyStorageLocation getKeyStorageLocation() {
        return KeyStorageLocation.SECURE;
    }

    @Override
    public boolean doesKeyExist() throws CryptoException {
        try {
            return mKeyStore.containsAlias(KEY_NAME);
        } catch (Exception ex) {
            throw new CryptoException("Failed to find key (RSA, secure keystore)", ex);
        }
    }

    @Override
    public void generateKey() throws CryptoException {
        Logging.getInstance().d(TAG, "generateKey: Generating key (RSA, secure keystore)");

        // expiry date longer than the lifetime of your phone
        final Calendar nowTime = Calendar.getInstance();
        final Calendar expiryTime = Calendar.getInstance();
        expiryTime.add(Calendar.YEAR, 25);

        try {
            final KeyPairGeneratorSpec keySpec = new KeyPairGeneratorSpec.Builder(mContext)
                    .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048, F4))
                    .setAlias(KEY_NAME)
                    .setSubject(new X500Principal("CN=" + KEY_NAME))
                    .setSerialNumber(BigInteger.TEN)
                    .setStartDate(nowTime.getTime())
                    .setEndDate(expiryTime.getTime())
                    .build();

            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, KEYSTORE_NAME);

            keyPairGenerator.initialize(keySpec);
            keyPairGenerator.generateKeyPair();

        } catch (Exception ex) {
            throw new CryptoException("Key generation failed (RSA, secure keystore)", ex);
        }

        Logging.getInstance().d(TAG, "generateKey: Key generation successful (RSA, secure keystore)");
    }

    @Override
    public void deleteKey() throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot delete key as it does not exist (RSA, secure keystore)");

        try {
            mKeyStore.deleteEntry(KEY_NAME);
        } catch (Exception ex) {
            throw new CryptoException("Delete failed (RSA, secure keystore)", ex);
        }
    }

    @Override
    public byte[][] encrypt(byte[][] plaintextArray) throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot find key for encryption (RSA, secure keystore)");

        final PublicKey publicKey = getPublicKey();

        final byte[][] ciphertextArray = new byte[plaintextArray.length][];
        try {
            final Cipher inputCipher = Cipher.getInstance(ALGORITHM_MODE);
            inputCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            for (int i = 0; i < plaintextArray.length; i++)
                ciphertextArray[i] = inputCipher.doFinal(plaintextArray[i]);

            return ciphertextArray;

        } catch (Exception ex) {
            throw new CryptoException("Encryption failed (RSA, secure keystore)", ex);
        }
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot find key for encryption (RSA, secure keystore)");

        final PublicKey publicKey = getPublicKey();

        try {
            final Cipher inputCipher = Cipher.getInstance(ALGORITHM_MODE);
            inputCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return inputCipher.doFinal(plaintext);

        } catch (Exception ex) {
            throw new CryptoException("Encryption failed (RSA, secure keystore)", ex);
        }
    }

    @Override
    public byte[][] decrypt(byte[][] ciphertextArray) throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot find key for encryption (RSA, secure keystore)");

        final PrivateKey privateKey = getPrivateKey();

        final byte[][] plaintextArray = new byte[ciphertextArray.length][];
        try {
            final Cipher outputCipher = Cipher.getInstance(ALGORITHM_MODE);
            outputCipher.init(Cipher.DECRYPT_MODE, privateKey);

            for (int i = 0; i < ciphertextArray.length; i++)
                plaintextArray[i] = outputCipher.doFinal(ciphertextArray[i]);

            return plaintextArray;

        } catch (Exception ex) {
            throw new CryptoException("Decryption failed (RSA, secure keystore)", ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot find key for encryption (RSA, secure keystore)");

        final PrivateKey privateKey = getPrivateKey();

        try {
            final Cipher outputCipher = Cipher.getInstance(ALGORITHM_MODE);
            outputCipher.init(Cipher.DECRYPT_MODE, privateKey);
            return outputCipher.doFinal(ciphertext);

        } catch (Exception ex) {
            throw new CryptoException("Decryption failed (RSA, secure keystore)", ex);
        }
    }

    private KeyStore initKeyStore() throws CryptoException {
        try {
            final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_NAME);
            keyStore.load(null);
            return keyStore;
        } catch (Exception ex) {
            throw new CryptoException("Keystore initialization failed (RSA, secure keystore)", ex);
        }
    }

    private PublicKey getPublicKey() throws CryptoException {
        try {
            final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)mKeyStore.getEntry(KEY_NAME, null);
            return privateKeyEntry.getCertificate().getPublicKey();
        } catch (Exception ex) {
            throw new CryptoException("Failed to load public key (RSA, secure keystore)", ex);
        }
    }

    private PrivateKey getPrivateKey() throws CryptoException {
        try {
            final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)mKeyStore.getEntry(KEY_NAME, null);
            return privateKeyEntry.getPrivateKey();
        } catch (Exception ex) {
            throw new CryptoException("Failed to load private key (RSA, secure keystore)", ex);
        }
    }

}
