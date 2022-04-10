package ca.j0e.passwordmanager;

import javax.crypto.SecretKey;

final class SecretKeyHolder {
    // Singleton pattern

    private SecretKey secretKey;
    private final static SecretKeyHolder INSTANCE = new SecretKeyHolder();

    private SecretKeyHolder() {}

    static SecretKeyHolder getInstance() {
        return INSTANCE;
    }

    SecretKey getSecretKey() {
        return secretKey;
    }

    void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }
}
