# Implementing Double (Hybrid) Encryption Using Asymmetric and Symmetric Keys in Java

This guide demonstrates how to implement a double (hybrid) encryption system in Java, combining asymmetric encryption with a server's public/private key pair and symmetric encryption using a client's secret key. It covers the process of encrypting data first with the server's public key, followed by the client's symmetric key, and then decrypting it in reverse order using the corresponding private and symmetric keys. This approach enhances data security by leveraging the strengths of both encryption methods.

## 1. Generate SSL Certificates
### 1.1 Generate Server's Public and Private Keys

You can use the Java `keytool` command to generate an SSL certificate for the server.

```shell
keytool -genkeypair -alias serverKeyPair -keyalg RSA -keysize 2048 -validity 365 -keystore serverKeystore.jks
```

This command creates a keystore file (`serverKeystore.jks`) containing the server's public/private key pair.

### 1.2 Export the Server's Public Key

You will need to export the server's public key to be used by the client.

```shell
keytool -exportcert -alias serverKeyPair -keystore serverKeystore.jks -file serverPublicKey.cer
```

This command creates a file (`serverPublicKey.cer`) containing the server's public key.

### 1.3 Generate the Client's Private Key

Similarly, you can create a symmetric key (which can act as the client's private key) using a different approach, like creating a secret key for symmetric encryption.

```shell
keytool -genseckey -alias clientSecretKey -keyalg AES -keysize 256 -keystore clientKeystore.jks
```

This command generates a symmetric key and stores it in the `clientKeystore.jks`.

---

## 2. Implement Double Encryption in Java

#### Explanation:
* **Server Public Key Loading**

>We load the server's public key from the certificate file using a CertificateFactory.

* **Asymmetric Encryption (RSA)**

> We use the server's public key to encrypt the data with RSA.

* **Client Symmetric Key Loading**

>The symmetric key is extracted from the client's keystore (`.jks`) file.

* **Symmetric Encryption (AES)**

>The data, already encrypted with RSA, is further encrypted using AES with the client’s symmetric key.

* **Base64 Encoding**

>The resulting encrypted data is encoded using Base64 for easy storage or transmission.

### 2.1 Load the Server's Public Key from `serverPublicKey.cer`

```java
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import javax.crypto.*;

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
    /* ... */

    /* Load the Client's Private (Symmetric) Key */
    /* ... */

    /* Encrypt the data again with Client's Symmetric Key (Symmetric Encryption) */
    /* ... */
}
```

### 2.2 Encrypt data with Server's Public Key (Asymmetric Encryption)

```java
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import javax.crypto.*;

public class EncryptUtils {
    /* Load the Server's Public Key */
    /* ... */

    /* Encrypt data with Server's Public Key (Asymmetric Encryption) */
    public static byte[] encryptWithPublicKey(PublicKey serverPublicKey, String dataToEncrypt) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedDataWithServerPublicKey = cipher.doFinal(dataToEncrypt.getBytes());

        return encryptedDataWithServerPublicKey;
    }

    /* Load the Client's Private (Symmetric) Key */
    /* ... */

    /* Encrypt the data again with Client's Symmetric Key (Symmetric Encryption) */
    /* ... */
}
```

### 2.3 Load the Client's Private (Symmetric) Key from `clientKeystore.jks`

```java
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import javax.crypto.*;

public class EncryptUtils {
    /* Load the Server's Public Key */
    /* ... */

    /* Encrypt data with Server's Public Key (Asymmetric Encryption) */
    /* ... */

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
    /* ... */
}
```

### 2.4 Encrypt data with Server's Public Key (Asymmetric Encryption)

```java
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import javax.crypto.*;

public class EncryptUtils {
    /* Load the Server's Public Key */
    /* ... */

    /* Encrypt data with Server's Public Key (Asymmetric Encryption) */
    /* ... */

    /* Load the Client's Private (Symmetric) Key */
    /* ... */

    /* Encrypt the data again with Client's Symmetric Key (Symmetric Encryption) */
    public static byte[] encryptWithSecretKey(SecretKey clientSecretKey, byte[] encryptedDataWithServerPublicKey) throws Exception {
        Cipher symmetricCipher = Cipher.getInstance("AES");
        symmetricCipher.init(Cipher.ENCRYPT_MODE, clientSecretKey);
        byte[] doubleEncryptedData = symmetricCipher.doFinal(encryptedDataWithServerPublicKey);

        return doubleEncryptedData;
    }
}
```

### 2.5 Double Encryption Main Method

```java
import javax.crypto.*;
import java.security.*;
import java.util.Base64;

public class DoubleEncryption {
    public static void main(String[] args) throws Exception {
        String serverPublicCertificateFile = "src/main/resources/serverPublicKey.cer";
        String clientKeyStoreFile = "src/main/resources/clientKeystore.jks";
        String clientKeyPassword = "123456";
        String clientKeyAlias = "clientSecretKey";

        String dataToEncrypt = "Sensitive Data";

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


        System.out.println("Data to Encrypt: " + dataToEncrypt);
        System.out.println("\nEncrypted Data With Public Key: " + new String(encryptedDataWithServerPublicKey));
        System.out.println("\nDouble Encrypted Data: " + new String(doubleEncryptedData));
        System.out.println("\nEncoded Double Encrypted Data: " + encodedEncryptedData);
    }
}
```

---

## 3. Implement Double Decryption in Java

#### Explanation:

* **Base64 Decoding**

> Decode Base64 to get the encrypted bytes.

* **Client Symmetric Key Loading**

> We load the symmetric key from the client's keystore (`.jks`) file.

* **Symmetric Decryption (AES)**

> The data, which was encrypted with the symmetric key, is decrypted using AES.

* **Server Private Key Loading**

> We load the server's private key from a `.jks` file. This private key should correspond to the public key used during the encryption.

* **Asymmetric Decryption (RSA)**

> The data is then decrypted using the server’s private key.

### 3.1 Load the Client's Private (Symmetric) Key from `clientKeystore.jks`

```java
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
    /* ... */

    /* Load the Server's Private Key */
    /* ... */

    /* Decrypt with the Server's Private Key (Asymmetric Decryption) */
    /* ... */
}
```

### 3.2 Decrypt with the Client's Symmetric Key (Symmetric Decryption)

```java
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

public class DecryptUtils {
    /* Load the Client's Private (Symmetric) Key */
    /* ... */

    /* Decrypt the double encrypted data with Client's Symmetric Key (Symmetric Decryption) */
    public static byte[] decryptWithSecretKey(SecretKey clientSecretKey, byte[] doubleEncryptedData) throws Exception {
        Cipher symmetricCipher = Cipher.getInstance("AES");
        symmetricCipher.init(Cipher.DECRYPT_MODE, clientSecretKey);
        byte[] decryptedDataWithSecretKey = symmetricCipher.doFinal(doubleEncryptedData);

        return decryptedDataWithSecretKey;
    }

    /* Load the Server's Private Key */
    /* ... */

    /* Decrypt with the Server's Private Key (Asymmetric Decryption) */
    /* ... */
}
```

### 3.3 Load the Server's Private Key from `serverKeystore.jks`

```java
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

public class DecryptUtils {
    /* Load the Client's Private (Symmetric) Key */
    /* ... */

    /* Decrypt the double encrypted data with Client's Symmetric Key (Symmetric Decryption) */
    /* ... */

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
    /* ... */
}
```

### 3.4 Decrypt with the Server's Private Key (Asymmetric Decryption)

```java
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;

public class DecryptUtils {
    /* Load the Client's Private (Symmetric) Key */
    /* ... */

    /* Decrypt the double encrypted data with Client's Symmetric Key (Symmetric Decryption) */
    /* ... */

    /* Load the Server's Private Key */
    /* ... */

    /* Decrypt with the Server's Private Key (Asymmetric Decryption) */
    public static byte[] decryptWithPrivateKey(PrivateKey serverPrivateKey, byte[] decryptedDataWithSecretKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
        byte[] originalData = rsaCipher.doFinal(decryptedDataWithSecretKey);

        return originalData;
    }
}
```

### 2.5 Double Decryption Main Method

```java
import javax.crypto.*;
import java.security.*;
import java.util.Base64;

public class DoubleDecryption {
    public static void main(String[] args) throws Exception {
        String serverKeyStoreFile = "src/main/resources/serverKeystore.jks";
        String serverKeyPassword = "123456";
        String serverKeyAlias = "serverKeyPair";
        String clientKeyStoreFile = "src/main/resources/clientKeystore.jks";
        String clientKeyPassword = "123456";
        String clientKeyAlias = "clientSecretKey";

        String encodedEncryptedData = "UZeO0WnYBrdlZbb6OB2bFk2yTTLzG1W3wky0P33EHYWzxQXCevNypEcJDyy9eDfGwdc/wwGz210IXhbEWJkBqfzBnsd1K7ALUB86bScSIv2cs2rxbjhoxhnNNsCntgu4JZOphzZTzlfLuhHhyaRwu17OlKVYmyulkLTQDlG/c9uThD4nq4IVte1g13NIGB7wc0MyPw2T5LJh0ChnQ58Vc2F8HyUTuiMr3iFb8Ro/BEYTzCTQlPaJWxnLT1Pv2TUeof4OcdhwDx6V19nwzZRs5Yh2SBEcpIg780WvUd8rIlstZXXs9rsWjKx8TPVzr4P4BRUtScUzef7f+MLdYo6ew/ZxaGecT58HXV1hBDWbF8U=";

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

        System.out.println("Encoded Double Encrypted Data: " + encodedEncryptedData);
        System.out.println("\nDouble Encrypted Data: " + new String(doubleEncryptedData));
        System.out.println("\nDecrypted Data With Secret Key: " + new String(decryptedDataWithSecretKey));
        System.out.println("\nOriginal Data: " + new String(originalData));
    }
}
```