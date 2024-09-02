package org.example.encryption;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.util.Base64;

public class DoubleEncryption {
    public static String doubleEncrypt(String dataToEncrypt) throws Exception {
        String serverPublicCertificateFile = "src/main/resources/serverPublicKey.cer";
        String clientKeyStoreFile = "src/main/resources/clientKeystore.jks";
        String clientKeyPassword = "123456";
        String clientKeyAlias = "clientSecretKey";

        // Step 1: Load the Server's Public Key
        PublicKey serverPublicKey = EncryptUtils.loadPublicKey(serverPublicCertificateFile);

        // Step 2: Encrypt data with Server's Public Key (Asymmetric Encryption)
        byte[] encryptedDataWithServerPublicKey = EncryptUtils.encryptWithPublicKey(serverPublicKey, dataToEncrypt);

        // Step 3: Load the Client's Symmetric Key from the KeyStore
        SecretKey clientSecretKey = EncryptUtils.loadSecretKey(clientKeyStoreFile, clientKeyPassword, clientKeyAlias);

        // Step 4: Encrypt the data again with Client's Symmetric Key (Symmetric Encryption)
        byte[] doubleEncryptedData = EncryptUtils.encryptWithSecretKey(clientSecretKey, encryptedDataWithServerPublicKey);

        // Step 5: Encode in Base64 for easy representation/storage
        String encodedEncryptedData = Base64.getEncoder().encodeToString(doubleEncryptedData);

        System.out.println("\nEncryption Process...");
        System.out.println("\nData to Encrypt: " + dataToEncrypt);
        System.out.println("\nEncrypted Data With Public Key: " + new String(encryptedDataWithServerPublicKey));
        System.out.println("\nDouble Encrypted Data: " + new String(doubleEncryptedData));
        System.out.println("\nEncoded Double Encrypted Data: " + encodedEncryptedData);

        return encodedEncryptedData;
    }
}
