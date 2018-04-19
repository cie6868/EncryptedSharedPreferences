package com.bucketscancompile.encryptedsharedpreferences;

import android.content.Context;

/**
 * Settings for {@link EncryptedSharedPreferences}.
 */
public abstract class EncryptedSharedPreferencesSettings {

    /**
     * Specifies the context used to access {@link android.content.SharedPreferences}.
     */
    public abstract Context context();

    /**
     * Sets the name of the {@link android.content.SharedPreferences} XML file used.
     */
    public abstract String preferencesName();

    /**
     * Specifies how to deal with invalid cryptographic keys.
     * For example, when the RSA keys change and the AES key is therefore unreadable.
     * If true, new keys will be generated.
     * If false, a {@link com.bucketscancompile.encryptedsharedpreferences.crypto.CryptoException} will be thrown.
     */
    public boolean allowCryptoKeyChange() { return false; }

    /**
     * Some devices do not support RSA key storage in the Trusted Excecution Environment (TEE).
     * If true, RSA keys will be stored in {@link android.content.SharedPreferences} instead (quite insecure).
     * If false, a {@link com.bucketscancompile.encryptedsharedpreferences.crypto.CryptoException} will be thrown.
     * Defaults to {@code false}.
     */
    public boolean allowInsecureRSAFallback() {
        return false;
    }

    /**
     * If false, the AES key is decrypted on demand. More secure but delivers a serious performance hit.
     * Defaults to {@code true}.
     */
    public boolean allowAesKeyInMemory() {
        return true;
    }

    /**
     * If false, debug messages will not be logged.
     * Defaults to {@code true}.
     */
    public boolean allowDebugLogs() {
        return true;
    }

}
