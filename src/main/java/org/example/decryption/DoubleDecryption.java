package org.example.decryption;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.util.Base64;

public class DoubleDecryption {
    public static void doubleDecrypt(String encodedEncryptedData) throws Exception {
        String serverKeyStoreFile = "src/main/resources/serverKeystore.jks";
        String serverKeyPassword = "123456";
        String serverKeyAlias = "serverKeyPair";
        String clientKeyStoreFile = "src/main/resources/clientKeystore.jks";
        String clientKeyPassword = "123456";
        String clientKeyAlias = "clientSecretKey";

        // Step 1: Decode Base64 to get the encrypted bytes
        byte[] doubleEncryptedData = Base64.getDecoder().decode(encodedEncryptedData);

        // Step 2: Load the Client's Symmetric Key from the KeyStore
        SecretKey clientSecretKey = DecryptUtils.loadSecretKey(clientKeyStoreFile, clientKeyPassword, clientKeyAlias);

        // Step 3: Decrypt with the Client's Symmetric Key (Symmetric Decryption)
        byte[] decryptedDataWithSecretKey = DecryptUtils.decryptWithSecretKey(clientSecretKey, doubleEncryptedData);

        // Step 4: Load the Server's Private Key from the Server Keystore
        PrivateKey serverPrivateKey = DecryptUtils.loadPrivateKey(serverKeyStoreFile, serverKeyPassword, serverKeyAlias);

        // Step 5: Decrypt with the Server's Private Key (Asymmetric Decryption)
        byte[] originalData = DecryptUtils.decryptWithPrivateKey(serverPrivateKey, decryptedDataWithSecretKey);

        System.out.println("\n--------------------------------");
        System.out.println("\nDecryption Process...");
        System.out.println("\nEncoded Double Encrypted Data: " + encodedEncryptedData);
        System.out.println("\nDouble Encrypted Data: " + new String(doubleEncryptedData));
        System.out.println("\nDecrypted Data With Secret Key: " + new String(decryptedDataWithSecretKey));
        System.out.println("\nOriginal Data: " + new String(originalData));
    }
}
