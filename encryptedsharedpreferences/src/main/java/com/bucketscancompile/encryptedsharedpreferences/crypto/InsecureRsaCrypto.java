package com.bucketscancompile.encryptedsharedpreferences.crypto;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;

import com.bucketscancompile.encryptedsharedpreferences.utils.Logging;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import static java.security.spec.RSAKeyGenParameterSpec.F4;

/**
 * Stores RSA keys in SharedPreferences. Anyone with root permission will be able to access the keys.
 * {@link com.bucketscancompile.encryptedsharedpreferences.RsaHelper} will use this as a fallback when {@link SecureRsaCrypto} fails.
 *
 * <br/><br/>
 *
 * This class exists because of the following bug:
 * <pre>
 *      java.security.ProviderException: Failed to load generated key pair from keystore
 *      at android.security.keystore.AndroidKeyStoreKeyPairGeneratorSpi.loadKeystoreKeyPair(AndroidKeyStoreKeyPairGeneratorSpi.java:518)
 *      at android.security.keystore.AndroidKeyStoreKeyPairGeneratorSpi.generateKeyPair(AndroidKeyStoreKeyPairGeneratorSpi.java:470)
 *      at java.security.KeyPairGenerator$Delegate.generateKeyPair(KeyPairGenerator.java:699)
 * </pre>
 *
 * Known to occur on some builds of LineageOS, one of which I use myself. See <a href="https://jira.lineageos.org/browse/BUGBASH-590">this bug report</a>.
 */
public class InsecureRsaCrypto extends Crypto {

    private static final String TAG = "InsecureRsaCrypto";

    private static final String PREFS = "ESPXmlKeyStore";
    private static final String KEY_NAME = "ESPRSA";
    private static final String KEY_NAME_PRIVATE = KEY_NAME + "private";
    private static final String KEY_NAME_PUBLIC = KEY_NAME + "public";
    private static final String ALGORITHM = "RSA";
    private static final String ALGORITHM_MODE = "RSA/ECB/PKCS1Padding";

    private SharedPreferences mPrefs;

    public InsecureRsaCrypto(Context context) throws CryptoException {
        super(context);

        mPrefs = mContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    @Override
    public KeyStorageLocation getKeyStorageLocation() {
        return KeyStorageLocation.XML;
    }

    @Override
    public boolean doesKeyExist() throws CryptoException {
        return mPrefs.contains(KEY_NAME_PRIVATE) && mPrefs.contains(KEY_NAME_PUBLIC);
    }

    @Override
    public void generateKey() throws CryptoException {
        Logging.getInstance().d(TAG, "generateKey: Generating key (RSA, keystore in preferences)");

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

            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);

            keyPairGenerator.initialize(keySpec.getAlgorithmParameterSpec());

            final KeyPair keyPair = keyPairGenerator.generateKeyPair();
            saveKeyPair(keyPair);

        } catch (Exception ex) {
            throw new CryptoException("Key generation failed (RSA, keystore in preferences)", ex);
        }


        Logging.getInstance().d(TAG, "generateKey: Key generation successful (RSA, keystore in preferences)");
    }

    @Override
    public void deleteKey() throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot delete key as it does not exist (RSA, keystore in preferences)");

        final SharedPreferences.Editor editor = mPrefs.edit();
        editor.remove(KEY_NAME_PUBLIC);
        editor.remove(KEY_NAME_PRIVATE);
        editor.commit();
    }

    @Override
    public byte[][] encrypt(byte[][] plaintextArray) throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot find key for encryption (RSA, keystore in preferences)");

        final PublicKey publicKey = getPublicKey();

        final byte[][] ciphertextArray = new byte[plaintextArray.length][];
        try {
            final Cipher inputCipher = Cipher.getInstance(ALGORITHM_MODE);
            inputCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            for (int i = 0; i < plaintextArray.length; i++)
                ciphertextArray[i] = inputCipher.doFinal(plaintextArray[i]);

            return ciphertextArray;

        } catch (Exception ex) {
            throw new CryptoException("Encryption failed (RSA, keystore in preferences)", ex);
        }
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot find key for encryption (RSA, keystore in preferences)");

        final PublicKey publicKey = getPublicKey();

        try {
            final Cipher inputCipher = Cipher.getInstance(ALGORITHM_MODE);
            inputCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return inputCipher.doFinal(plaintext);

        } catch (Exception ex) {
            throw new CryptoException("Encryption failed (RSA, keystore in preferences)", ex);
        }
    }

    @Override
    public byte[][] decrypt(byte[][] ciphertextArray) throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot find key for decryption (RSA, keystore in preferences)");

        final PrivateKey privateKey = getPrivateKey();

        final byte[][] plaintextArray = new byte[ciphertextArray.length][];
        try {
            final Cipher outputCipher = Cipher.getInstance(ALGORITHM_MODE);
            outputCipher.init(Cipher.DECRYPT_MODE, privateKey);

            for (int i = 0; i < ciphertextArray.length; i++)
                plaintextArray[i] = outputCipher.doFinal(ciphertextArray[i]);

            return plaintextArray;

        } catch (Exception ex) {
            throw new CryptoException("Decryption failed (RSA, keystore in preferences)", ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) throws CryptoException {
        if (!doesKeyExist())
            throw new CryptoException("Cannot find key for decryption (RSA, keystore in preferences)");

        final PrivateKey privateKey = getPrivateKey();

        try {
            final Cipher outputCipher = Cipher.getInstance(ALGORITHM_MODE);
            outputCipher.init(Cipher.DECRYPT_MODE, privateKey);
            return outputCipher.doFinal(ciphertext);

        } catch (Exception ex) {
            throw new CryptoException("Decryption failed (RSA, keystore in preferences)", ex);
        }
    }

    private PublicKey getPublicKey() throws CryptoException {
        final String publicKeyString = mPrefs.getString(KEY_NAME_PUBLIC, "");

        if (publicKeyString.equals(""))
            throw new CryptoException("Public key was empty in SharedPreferences (RSA, keystore in preferences)");

        final byte[] publicKeyBytes = Base64.decode(publicKeyString, Base64.NO_WRAP);

        try {
            final KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            return kf.generatePublic(keySpec);
        } catch (Exception ex) {
            throw new CryptoException("Failed to load public key (RSA, keystore in preferences)", ex);
        }
    }

    private PrivateKey getPrivateKey() throws CryptoException {
        final String privateKeyString = mPrefs.getString(KEY_NAME_PRIVATE, "");

        if (privateKeyString.equals(""))
            throw new CryptoException("Private key was empty in SharedPreferences (RSA, keystore in preferences)");

        final byte[] privateKeyBytes = Base64.decode(privateKeyString, Base64.NO_WRAP);

        try {
            final KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
            final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return kf.generatePrivate(keySpec);
        } catch (Exception ex) {
            throw new CryptoException("Failed to load private key (RSA, keystore in preferences)", ex);
        }
    }

    private void saveKeyPair(KeyPair keyPair) {
        final byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        final String publicKeyString = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP);

        final byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        final String privateKeyString = Base64.encodeToString(privateKeyBytes, Base64.NO_WRAP);

        final SharedPreferences.Editor editor = mPrefs.edit();
        editor.putString(KEY_NAME_PUBLIC, publicKeyString);
        editor.putString(KEY_NAME_PRIVATE, privateKeyString);
        editor.commit();
    }

}
