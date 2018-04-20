package com.bucketscancompile.encryptedsharedpreferences;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.bucketscancompile.encryptedsharedpreferences.crypto.Crypto;
import com.bucketscancompile.encryptedsharedpreferences.crypto.CryptoException;
import com.bucketscancompile.encryptedsharedpreferences.crypto.LegacyAesCrypto;
import com.bucketscancompile.encryptedsharedpreferences.utils.Logging;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A wrapper of {@link SharedPreferences} to provide cryptographic security.
 * The intention is to obfuscate the XML file that stores this data.
 * Ideally an attacker with root access to the device will be unable to read or modify the contents.
 *
 * <br><br>
 *
 * Keys are stored as hashes, with a fixed salt protected by AES encryption.
 * RSA encryption is used to protect the AES key. The RSA keys are stored in hardware-backed secure storage in most devices.
 * Values are stored as AES-encrypted strings.
 * Denying {@code allowKeyInMemory} will minimise how long the decrypted AES key is kept in memory, but at a heavy performance penalty.
 *
 * <br><br>
 *
 * Null values will be ignored in most cases, despite allowing nullable values for compatibility with {@link SharedPreferences}.
 * Cryptographic faults will result in a null output or no data modifications. The causes will get logged to debug.
 *
 * <br><br>
 *
 * The key names and data types must be known in order to access the corresponding values correctly.
 * Due to the one-way hashing of keys, {@link #getAll()} is not implemented as it would output nonsense keys.
 * {@link android.content.SharedPreferences.OnSharedPreferenceChangeListener} is yet to be implemented.
 * None of the methods throw {@link ClassCastException}; instead null is returned when a key is not found.
 *
 * @see android.content.SharedPreferences
 */
public class EncryptedSharedPreferences implements SharedPreferences {

    private static final String TAG = "EncryptedShdPrfs";

    private final EncryptedSharedPreferencesSettings mSettings;
    private final Context mContext;
    private final SharedPreferences mPrefs;
    private final Crypto mAesCrypto;
    private final KeyHasher mKeyHasher;

    /**
     * Initializes access to encrypted key-value pairs.
     * @param settings An {@link EncryptedSharedPreferencesSettings} object
     */
    public EncryptedSharedPreferences(@NonNull EncryptedSharedPreferencesSettings settings) throws CryptoException {
        mSettings = settings;

        Logging.create(mSettings.allowDebugLogs());
        mContext = mSettings.context();
        mPrefs = mContext.getSharedPreferences(settings.preferencesName(), Context.MODE_PRIVATE);

        final Crypto rsa = setupRsa();

        mAesCrypto = setupAes(rsa);
        mKeyHasher = setupHasher();
    }

    private Crypto setupRsa() throws CryptoException {
        Crypto rsa;
        try {
            rsa = RsaHelper.getExistingCrypto(mContext, mSettings.allowInsecureRSAFallback());
        } catch (CryptoException ex) {
            // unknown error, try making new keys or switching to insecure if permitted
            if (mSettings.allowCryptoKeyChange())
                rsa = generateRsa();
            else
                throw new CryptoException("RSA keys could not be read and allowCryptoKeyChange is false", ex);
        }

        // if no keys found, always generate new keys
        if (rsa == null)
            rsa = generateRsa();

        return rsa;
    }

    private Crypto generateRsa() throws CryptoException {
        final Crypto rsa = RsaHelper.generateCrypto(mContext, mSettings.allowInsecureRSAFallback());
        if (rsa == null)
            throw new CryptoException("RSA key generation failed and allowInsecureRSAFallback is " + mSettings.allowInsecureRSAFallback());
        else
            return rsa;
    }

    private Crypto setupAes(Crypto rsa) throws CryptoException {
        final Crypto aes = new LegacyAesCrypto(mContext, rsa, mSettings.allowAesKeyInMemory());

        boolean keyExists;
        try {
            keyExists = aes.doesKeyExist();
        } catch (CryptoException ex) {
            // decryption error
            if (mSettings.allowCryptoKeyChange()) {
                aes.generateKey();
                keyExists = aes.doesKeyExist();
            } else
                throw new CryptoException("AES key could not be decrypted and allowCryptoKeyChange is false", ex);
        }

        // if no key found, always generate new one
        if (!keyExists)
            aes.generateKey();

        return aes;
    }

    private KeyHasher setupHasher() throws CryptoException {
        final KeyHasher hasher = new KeyHasher(mContext, mAesCrypto);

        boolean saltExists;
        try {
            saltExists = hasher.doesSaltExist();
        } catch (CryptoException ex) {
            // decryption error
            if (mSettings.allowCryptoKeyChange()) {
                hasher.generateSalt();
                saltExists = hasher.doesSaltExist();
            } else
                throw new CryptoException("Hashing salt could not be decrypted and allowCryptoKeyChange is false", ex);
        }

        // if no salt found, always generate new one
        if (!saltExists)
            hasher.generateSalt();

        return hasher;
    }

    private String getHashedKey(String key) {
        try {
            return mKeyHasher.hash(key);
        } catch (Exception ex) {
            Logging.getInstance().e(TAG, "getHashedKey: Failed", ex);
            return null;
        }
    }

    private String getDecryptedValue(String encryptedValue) {
        if (encryptedValue == null) {
            Logging.getInstance().e(TAG, "getDecryptedValue: Encrypted input is null");
            return null;
        }

        try {
            return mAesCrypto.decrypt(encryptedValue);
        } catch (CryptoException ex) {
            Logging.getInstance().e(TAG, "getDecryptedValue: Failed", ex);
            return null;
        }
    }

    private String getEncryptedValue(String value) {
        if (value == null) {
            Logging.getInstance().e(TAG, "getEncryptedValue: Unencrypted input is null");
            return null;
        }

        try {
            return mAesCrypto.encrypt(value);
        } catch (CryptoException ex) {
            Logging.getInstance().e(TAG, "getEncryptedValue: Failed", ex);
            return null;
        }
    }

    /**
     * Cannot be implemented as keys are one-way hashed. The {@link Map} keys would contain nonsense.
     * @return {@link UnsupportedOperationException}
     */
    public Map<String, ?> getAll() {
        throw new UnsupportedOperationException("Unsupported due to one-way key hashing");
    }

    @Nullable
    public String getString(String key, @Nullable String defValue) {
        final String hashedKey = getHashedKey(key);
        if (hashedKey == null)
            return defValue;

        final String encryptedValue = mPrefs.getString(hashedKey, null);
        final String decryptedValueString = getDecryptedValue(encryptedValue);
        if (decryptedValueString == null)
            return defValue;
        else
            return decryptedValueString;
    }

    @Nullable
    public Set<String> getStringSet(String key, @Nullable Set<String> defValues) {
        final String hashedKey = getHashedKey(key);
        if (hashedKey == null)
            return defValues;

        final Set<String> encryptedValues = mPrefs.getStringSet(hashedKey, null);
        if (encryptedValues == null)
            return defValues;

        try {
            return mAesCrypto.decrypt(encryptedValues);
        } catch (CryptoException ex) {
            Logging.getInstance().e(TAG, "getStringSet: Failed", ex);
            return defValues;
        }
    }

    public int getInt(String key, int defValue) {
        final String hashedKey = getHashedKey(key);
        if (hashedKey == null)
            return defValue;

        final String encryptedValue = mPrefs.getString(hashedKey, null);
        final String decryptedValueString = getDecryptedValue(encryptedValue);
        if (decryptedValueString == null)
            return defValue;
        else
            return Integer.parseInt(decryptedValueString);
    }

    public long getLong(String key, long defValue) {
        final String hashedKey = getHashedKey(key);
        if (hashedKey == null)
            return defValue;

        final String encryptedValue = mPrefs.getString(hashedKey, null);
        final String decryptedValueString = getDecryptedValue(encryptedValue);
        if (decryptedValueString == null)
            return defValue;
        else
            return Long.parseLong(decryptedValueString);
    }

    public float getFloat(String key, float defValue) {
        final String hashedKey = getHashedKey(key);
        if (hashedKey == null)
            return defValue;

        final String encryptedValue = mPrefs.getString(hashedKey, null);
        final String decryptedValueString = getDecryptedValue(encryptedValue);
        if (decryptedValueString == null)
            return defValue;
        else
            return Float.parseFloat(decryptedValueString);
    }

    public boolean getBoolean(String key, boolean defValue) {
        final String hashedKey = getHashedKey(key);
        if (hashedKey == null)
            return defValue;

        final String encryptedValue = mPrefs.getString(hashedKey, null);
        final String decryptedValueString = getDecryptedValue(encryptedValue);
        if (decryptedValueString == null)
            return defValue;
        else
            return Boolean.parseBoolean(decryptedValueString);
    }

    public boolean contains(String key) {
        final String hashedKey = getHashedKey(key);
        return hashedKey != null && mPrefs.contains(hashedKey);
    }

    /**
     * See {@link Editor}.
     */
    public Editor edit() {
        return new Editor();
    }

    /**
     * Not implemented yet.
     * @throws UnsupportedOperationException As operation is not implemented yet
     */
    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     * Not implemented yet.
     * @throws UnsupportedOperationException As operation is not implemented yet
     */
    public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     * Provides functions to edit {@link EncryptedSharedPreferences}.
     * Changes are queued and processed as a batch.
     */
    public class Editor implements SharedPreferences.Editor {

        private static final String TAG = "EncryptedShdPrfs.Editor";

        private final Map<String, String> mModified;
        private final Map<String, Set<String>> mStringSets;
        private final Set<String> mRemovedKeys;
        private boolean mClearRequested;

        private Editor() {
            mModified = new HashMap<>();
            mStringSets = new HashMap<>();
            mRemovedKeys = new HashSet<>();
            mClearRequested = false;
        }

        /**
         * @param value Passing null will result in no modifications being made.
         */
        public Editor putString(String key, @Nullable String value) {
            if (value != null)
                mModified.put(key, value);

            return this;
        }

        public Editor putStringSet(String key, @Nullable Set<String> values) {
            if (values != null)
                mStringSets.put(key, values);

            return this;
        }

        public Editor putInt(String key, int value) {
            mModified.put(key, Integer.toString(value));
            return this;
        }

        public Editor putLong(String key, long value) {
            mModified.put(key, Long.toString(value));
            return this;
        }

        public Editor putFloat(String key, float value) {
            mModified.put(key, Float.toString(value));
            return this;
        }

        public Editor putBoolean(String key, boolean value) {
            mModified.put(key, Boolean.toString(value));
            return this;
        }

        public Editor remove(String key) {
            mRemovedKeys.add(key);
            return this;
        }

        public Editor clear() {
            mClearRequested = true;
            return this;
        }

        public boolean commit() {
            // commit inside try block so that no commits are made if there is a failure
            try {
                return doModifications().commit();
            } catch (CryptoException ex) {
                Logging.getInstance().e(TAG, "commit: Failed to commit changes", ex);
                return false;
            }
        }

        public void apply() {
            // apply inside try block so that no commits are made if there is a failure
            try {
                doModifications().apply();
            } catch (CryptoException ex) {
                Logging.getInstance().e(TAG, "apply: Failed to apply changes", ex);
            }
        }

        private SharedPreferences.Editor doModifications() throws CryptoException {
            final SharedPreferences.Editor editor = mPrefs.edit();

            // clear
            if (mClearRequested)
                editor.clear();

            // remove
            final Set<String> deleteHashedKeys = mKeyHasher.hashBatch(mRemovedKeys);
            for (String hashedKey : deleteHashedKeys)
                editor.remove(hashedKey);

            // modify (batch hashing and encryption)
            doKeyValueModifications(editor);

            // modify string sets
            doStringSetModifications(editor);

            return editor;
        }

        private void doKeyValueModifications(SharedPreferences.Editor editor) throws CryptoException {
            final List<String> hashedKeysList = new ArrayList<>(mKeyHasher.hashBatch(mModified.keySet()));
            final Set<String> valuesSet = new LinkedHashSet<>(mModified.values());
            final List<String> encryptedValuesList = new ArrayList<>(mAesCrypto.encrypt(valuesSet));

            for (int i = 0; i < hashedKeysList.size(); i++) {
                if (hashedKeysList.get(i) == null)
                    continue;
                editor.putString(hashedKeysList.get(i), encryptedValuesList.get(i));
            }
        }

        private void doStringSetModifications(SharedPreferences.Editor editor) throws CryptoException {
            final List<String> hashedKeysList = new ArrayList<>(mKeyHasher.hashBatch(mStringSets.keySet()));
            final List<Set<String>> valuesList = new ArrayList<>(mStringSets.values());

            for (int i = 0; i < hashedKeysList.size(); i++) {
                if (hashedKeysList.get(i) == null)
                    continue;
                editor.putStringSet(hashedKeysList.get(i), mAesCrypto.encrypt(valuesList.get(i)));
            }
        }
    }

}
