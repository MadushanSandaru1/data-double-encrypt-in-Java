package org.example.encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;

public class EncryptUtils {
    /* Load the Server's Public Key */
    public static PublicKey loadPublicKey(String serverPublicCertificateFile) throws Exception {
        FileInputStream fis = new FileInputStream(serverPublicCertificateFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        PublicKey serverPublicKey = cf.generateCertificate(fis).getPublicKey();
        fis.close();

        return serverPublicKey;
    }

    /* Encrypt data with Server's Public Key (Asymmetric Encryption) */
    public static byte[] encryptWithPublicKey(PublicKey serverPublicKey, String dataToEncrypt) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedDataWithServerPublicKey = cipher.doFinal(dataToEncrypt.getBytes());

        return encryptedDataWithServerPublicKey;
    }

    /* Load the Client's Private (Symmetric) Key */
    public static SecretKey loadSecretKey(String clientKeyStoreFile, String clientKeyPassword, String clientKeyAlias) throws Exception {
        FileInputStream keyStoreStream = new FileInputStream(clientKeyStoreFile);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(keyStoreStream, clientKeyPassword.toCharArray());
        SecretKey clientSecretKey = (SecretKey) keyStore.getKey(clientKeyAlias, clientKeyPassword.toCharArray());
        keyStoreStream.close();

        return clientSecretKey;
    }

    /* Encrypt the data again with Client's Symmetric Key (Symmetric Encryption) */
    public static byte[] encryptWithSecretKey(SecretKey clientSecretKey, byte[] encryptedDataWithServerPublicKey) throws Exception {
        Cipher symmetricCipher = Cipher.getInstance("AES");
        symmetricCipher.init(Cipher.ENCRYPT_MODE, clientSecretKey);
        byte[] doubleEncryptedData = symmetricCipher.doFinal(encryptedDataWithServerPublicKey);

        return doubleEncryptedData;
    }
}
