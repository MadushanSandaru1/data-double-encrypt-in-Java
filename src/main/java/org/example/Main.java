package org.example;

import org.example.decryption.DoubleDecryption;
import org.example.encryption.DoubleEncryption;

public class Main {
    public static void main(String[] args) throws Exception {
        String dataToEncrypt = "Sensitive Data";
        String encodedEncryptedData = DoubleEncryption.doubleEncrypt(dataToEncrypt);
        DoubleDecryption.doubleDecrypt(encodedEncryptedData);
    }
}
