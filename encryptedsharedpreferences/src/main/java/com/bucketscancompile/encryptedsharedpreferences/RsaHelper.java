package com.bucketscancompile.encryptedsharedpreferences;

import android.content.Context;

import com.bucketscancompile.encryptedsharedpreferences.crypto.Crypto;
import com.bucketscancompile.encryptedsharedpreferences.crypto.CryptoException;
import com.bucketscancompile.encryptedsharedpreferences.crypto.InsecureRsaCrypto;
import com.bucketscancompile.encryptedsharedpreferences.crypto.SecureRsaCrypto;
import com.bucketscancompile.encryptedsharedpreferences.utils.Logging;

/**
 * Convenience methods for working with {@link SecureRsaCrypto} and {@link InsecureRsaCrypto}.
 * Will attempt to use {@link SecureRsaCrypto} first.
 */
class RsaHelper {

    private static final String TAG = "RsaHelper";

    /**
     * Returns a {@link SecureRsaCrypto} or {@link InsecureRsaCrypto} as appropriate.
     * Return null if there are no keys found on the device.
     * @param context Context
     * @param allowInsecure If true, automatic fallback to insecure key storage if secure storage fails
     * @return {@link Crypto} object or null
     * @throws CryptoException On technical failure while checking for key in SharedPreferences
     */
    static Crypto getExistingCrypto(Context context, boolean allowInsecure) throws CryptoException {
        try {
            final SecureRsaCrypto secureCrypto = new SecureRsaCrypto(context);
            if (secureCrypto.doesKeyExist()) {
                Logging.getInstance().d(TAG, "getExistingCrypto: Keys found in secure storage");
                return secureCrypto;
            }
        } catch (CryptoException ex) {
            Logging.getInstance().d(TAG, "getExistingCrypto: Failed to access secure key storage", ex);
        }

        if (!allowInsecure)
            return null;

        final InsecureRsaCrypto insecureCrypto = new InsecureRsaCrypto(context);
        if (insecureCrypto.doesKeyExist()) {
            Logging.getInstance().d(TAG, "getExistingCrypto: Keys found in xml");
            return insecureCrypto;
        }

        Logging.getInstance().d(TAG, "getExistingCrypto: No keys were found");
        return null;
    }

    /**
     * Generates RSA keys and returns a {@link SecureRsaCrypto} or {@link InsecureRsaCrypto} as appropriate.
     * @param context Context
     * @param allowInsecure If true, automatic fallback to insecure key storage if secure storage fails
     * @return {@link Crypto} object
     * @throws CryptoException On technical failure while generating or storing key in SharedPreferences
     */
    static Crypto generateCrypto(Context context, boolean allowInsecure) throws CryptoException {
        try {
            final SecureRsaCrypto secureCrypto = new SecureRsaCrypto(context);
            secureCrypto.generateKey();
            return secureCrypto;
        } catch (CryptoException ex) {
            Logging.getInstance().d(TAG, "getExistingCrypto: Failed to generate key in secure storage", ex);
        }

        if (!allowInsecure)
            return null;

        final InsecureRsaCrypto insecureCrypto = new InsecureRsaCrypto(context);
        insecureCrypto.generateKey();
        return insecureCrypto;
    }

}
