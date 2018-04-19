package com.bucketscancompile.encryptedsharedpreferences.crypto;

public enum KeyStorageLocation {

    NONE,       // no key
    SECURE,     // AndroidKeyStore
    XML         // SharedPreferences

}
