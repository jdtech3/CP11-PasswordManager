package ca.j0e.passwordmanager;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.stage.Stage;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ResourceBundle;

public class LoginController implements Initializable {
    @FXML
    private PasswordField passwordField;

    @FXML
    private Button loginButton;

    @FXML
    protected void login() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String password = passwordField.getText();

        // Check password against hash
        Base64SHA512Hash storedHash = IOHandler.loadHash();
        Base64SHA512Hash newHash = CryptoHandler.generateHash(password, storedHash.getRawSalt());
        if (newHash.getHash().equals(storedHash.getHash())) {
            // Generate AES secret key
            SecretKey secretKey = CryptoHandler.generateSecret(password, storedHash.getRawSalt());

            // Pass on using singleton
            SecretKeyHolder secretKeyHolder = SecretKeyHolder.getInstance();
            secretKeyHolder.setSecretKey(secretKey);

            FXMLLoader fxmlLoader = new FXMLLoader(PasswordManagerApplication.class.getResource("main-view.fxml"));
            Scene scene = new Scene(fxmlLoader.load(), 640, 480);
            Stage stage = (Stage) passwordField.getScene().getWindow();
            stage.setTitle("Password Manager");
            stage.setScene(scene);
            stage.show();
        }
        else {
            passwordField.clear();
            loginButton.setText("(Wrong password!) Try again");
        }
    }

    @FXML
    protected void newPassword() throws NoSuchAlgorithmException, IOException {
        // Generate new hash and store
        String password = passwordField.getText();
        IOHandler.saveHash(CryptoHandler.generateHash(password, CryptoHandler.generateSalt()));

        // TODO: Clear old data

        loginButton.setDisable(false);  // re-enable login button
    }

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        if (IOHandler.loadHash() == null) loginButton.setDisable(true);     // if no/invalid hash.txt, disallow login
    }
}
