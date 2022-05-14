package ca.j0e.passwordmanager;

import java.util.Base64;

public class Base64Ciphertext {
    private final String ciphertext;
    private final String iv;

    Base64Ciphertext(String ciphertext, String iv) {
        this.ciphertext = ciphertext;
        this.iv = iv;
    }

    public String getCiphertext() {
        return ciphertext;
    }

    public String getIv() {
        return iv;
    }

    public byte[] getRawCiphertext() { return Base64.getDecoder().decode(ciphertext); }

    public byte[] getRawIv() {
        return Base64.getDecoder().decode(iv);
    }
}
