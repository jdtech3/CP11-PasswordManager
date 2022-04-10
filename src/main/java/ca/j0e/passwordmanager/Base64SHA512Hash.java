package ca.j0e.passwordmanager;

import java.util.Base64;

public class Base64SHA512Hash {
    private final String hash;
    private final String salt;

    Base64SHA512Hash(String hash, String salt) {
        this.hash = hash;
        this.salt = salt;
    }

    public String getHash() {
        return hash;
    }

    public String getSalt() {
        return salt;
    }

    public byte[] getRawSalt() {
        return Base64.getDecoder().decode(salt);
    }
}
