package ca.j0e.passwordmanager;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class CryptoHandler {
    private static final SecureRandom random = new SecureRandom();

    /**
     * Generates an 8-byte salt
     * @return salt
     */
    static byte[] generateSalt() {
        byte[] salt = new byte[8];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Generates an AES secret key from PBKDF2-HMAC-SHA256 hash of password and salt
     * @param password password
     * @param salt salt to use (use generateSalt())
     * @return secret key
     * @throws NoSuchAlgorithmException passed on from crypto lib
     * @throws InvalidKeySpecException passed on from crypto lib
     */
    static SecretKey generateSecret(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);

        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    /**
     * Generates Base64-encoded SHA-512 hashes
     * @param password password to hash
     * @param salt salt to use (use generateSalt())
     * @return Base64-encoded hash and salt
     * @throws NoSuchAlgorithmException passed on from crypto lib
     */
    static Base64SHA512Hash generateHash(String password, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(salt);
        byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));

        return new Base64SHA512Hash(Base64.getEncoder().encodeToString(hash), Base64.getEncoder().encodeToString(salt));
    }
}
