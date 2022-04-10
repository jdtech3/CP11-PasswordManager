package ca.j0e.passwordmanager;

import javafx.scene.control.ListView;

import java.io.*;

public class IOHandler {
    /*
        Password validation file spec:
            hash.txt file
            1 line
            salt and hash separated by colon
     */

    static Base64SHA512Hash loadHash() {
        String line;

        try {
            // Open the file
            FileReader fr = new FileReader("hash.txt");
            BufferedReader br = new BufferedReader(fr);

            // Read first line and close readers
            line = br.readLine();
            br.close();
        }
        catch (IOException e) {
            return null;
        }

        // Split by colon delimiter, construct obj
        if (line != null) {
            String[] raw = line.split(":");
            return new Base64SHA512Hash(raw[0], raw[1]);
        }
        else {
            return null;
        }
    }

    static void saveHash(Base64SHA512Hash hash) throws IOException {
        String line = String.format("%s:%s", hash.getHash(), hash.getSalt());

        // Open the file
        FileWriter fr = new FileWriter("hash.txt");     // overwrite
        BufferedWriter br = new BufferedWriter(fr);

        // Read line and close readers
        br.write(line);
        br.close();
    }
}
