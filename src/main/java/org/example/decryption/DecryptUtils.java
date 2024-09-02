package org.example.decryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

public class DecryptUtils {
    /* Load the Client's Private (Symmetric) Key */
    public static SecretKey loadSecretKey(String clientKeyStoreFile, String clientKeyPassword, String clientKeyAlias) throws Exception {
        FileInputStream fis = new FileInputStream(clientKeyStoreFile);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(fis, clientKeyPassword.toCharArray());

        return (SecretKey) keystore.getKey(clientKeyAlias, clientKeyPassword.toCharArray());
    }

    /* Decrypt the double encrypted data with Client's Symmetric Key (Symmetric Decryption) */
    public static byte[] decryptWithSecretKey(SecretKey clientSecretKey, byte[] doubleEncryptedData) throws Exception {
        Cipher symmetricCipher = Cipher.getInstance("AES");
        symmetricCipher.init(Cipher.DECRYPT_MODE, clientSecretKey);
        byte[] decryptedDataWithSecretKey = symmetricCipher.doFinal(doubleEncryptedData);

        return decryptedDataWithSecretKey;
    }

    /* Load the Server's Private Key */
    public static PrivateKey loadPrivateKey(String serverKeyStoreFile, String serverKeyPassword, String serverKeyAlias) throws Exception {
        FileInputStream serverKeyStoreStream = new FileInputStream(serverKeyStoreFile);
        KeyStore serverKeyStore = KeyStore.getInstance("JKS");
        serverKeyStore.load(serverKeyStoreStream, serverKeyPassword.toCharArray());
        PrivateKey serverPrivateKey = (PrivateKey) serverKeyStore.getKey(serverKeyAlias, serverKeyPassword.toCharArray());
        serverKeyStoreStream.close();

        return serverPrivateKey;
    }

    /* Decrypt with the Server's Private Key (Asymmetric Decryption) */
    public static byte[] decryptWithPrivateKey(PrivateKey serverPrivateKey, byte[] decryptedDataWithSecretKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
        byte[] originalData = rsaCipher.doFinal(decryptedDataWithSecretKey);

        return originalData;
    }
}
