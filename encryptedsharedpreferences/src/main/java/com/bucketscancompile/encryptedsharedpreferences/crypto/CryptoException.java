package com.bucketscancompile.encryptedsharedpreferences.crypto;

public class CryptoException extends Exception {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable ex) {
        super(message, ex);
    }

}
