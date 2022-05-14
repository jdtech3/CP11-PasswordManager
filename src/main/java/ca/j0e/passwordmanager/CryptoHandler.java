package ca.j0e.passwordmanager;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

// TODO: Consolidate exceptions from javax.crypto into single custom exception?

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

    /**
     * Encrypts plaintext with given secret key
     * @param plaintext plaintext to encrypt
     * @param key secret key to use (use generateSecret())
     * @return Base64-encoded ciphertext and init vector
     * @throws NoSuchAlgorithmException passed on from crypto lib
     * @throws NoSuchPaddingException passed on from crypto lib
     * @throws InvalidKeyException passed on from crypto lib
     * @throws InvalidParameterSpecException passed on from crypto lib
     * @throws IllegalBlockSizeException passed on from crypto lib
     * @throws BadPaddingException passed on from crypto lib
     */
    static Base64Ciphertext encrypt(String plaintext, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        return new Base64Ciphertext(Base64.getEncoder().encodeToString(ciphertext), Base64.getEncoder().encodeToString(iv));
    }

    /**
     * Decrypts ciphertext/IV with given secret key
     * @param ciphertext Base64-encoded ciphertext and init vector
     * @param key secret key to use
     * @return Plaintext string
     * @throws NoSuchPaddingException passed on from crypto lib
     * @throws NoSuchAlgorithmException passed on from crypto lib
     * @throws InvalidKeyException passed on from crypto lib
     * @throws IllegalBlockSizeException passed on from crypto lib
     * @throws BadPaddingException passed on from crypto lib
     * @throws InvalidAlgorithmParameterException passed on from crypto lib
     */
    static String decrypt(Base64Ciphertext ciphertext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ciphertext.getRawIv()));

        return new String(cipher.doFinal(ciphertext.getRawCiphertext()), StandardCharsets.UTF_8);
    }
}
