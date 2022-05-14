package ca.j0e.passwordmanager;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import static org.junit.jupiter.api.Assertions.*;

class CryptoHandlerTest {
    @Test
    void endToEndEncryptDecryptTest() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, InvalidParameterSpecException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        // Generate test key and ciphertext
        SecretKey testKey = CryptoHandler.generateSecret("test password", CryptoHandler.generateSalt());
        Base64Ciphertext ciphertext = CryptoHandler.encrypt("test plaintext", testKey);

        // Make sure ciphertext decrypts correctly
        assertEquals(CryptoHandler.decrypt(ciphertext, testKey), "test plaintext");
    }
}
