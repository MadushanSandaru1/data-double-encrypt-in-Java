# Data double encrypt in Java Using RSA and AES

To create a data double encryption scheme in Java where you first encrypt data using the server's public key (asymmetric encryption) and then with the client's private key (symmetric encryption), you'll need to follow several steps:

### Step 1: Generate SSL Certificates
#### 1.1 Generate Server's Public and Private Keys

You can use the Java `keytool` command to generate an SSL certificate for the server.

```shell
keytool -genkeypair -alias serverKeyPair -keyalg RSA -keysize 2048 -validity 365 -keystore serverKeystore.jks
```

This command creates a keystore file (`serverKeystore.jks`) containing the server's public/private key pair.

#### 1.2 Export the Server's Public Key

You will need to export the server's public key to be used by the client.

```shell
keytool -exportcert -alias serverKeyPair -keystore serverKeystore.jks -file serverPublicKey.cer
```

This command creates a file (`serverPublicKey.cer`) containing the server's public key.

#### 1.3 Generate the Client's Private Key

Similarly, you can create a symmetric key (which can act as the client's private key) using a different approach, like creating a secret key for symmetric encryption.

```shell
keytool -genseckey -alias clientSecretKey -keyalg AES -keysize 256 -keystore clientKeystore.jks
```

This command generates a symmetric key and stores it in the `clientKeystore.jks`.

---

### Step 2: Implement Encryption in Java

#### 2.1 Load the Server's Public Key

You can load the server's public key using Java's `KeyStore` class.

```java
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;

public class PublicKeyLoader {
    public static PublicKey loadPublicKey(String keystoreFile, String alias, String keystorePassword) throws Exception {
        FileInputStream fis = new FileInputStream(keystoreFile);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(fis, keystorePassword.toCharArray());

        Certificate cert = keystore.getCertificate(alias);
        return cert.getPublicKey();
    }
}
```

#### 2.2 Load the Client's Private (Symmetric) Key

Similarly, load the client's private key (symmetric key) from the keystore.

```java
import java.io.FileInputStream;
import java.security.KeyStore;
import javax.crypto.SecretKey;

public class SecretKeyLoader {
    public static SecretKey loadSecretKey(String keystoreFile, String alias, String keystorePassword) throws Exception {
        FileInputStream fis = new FileInputStream(keystoreFile);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(fis, keystorePassword.toCharArray());

        return (SecretKey) keystore.getKey(alias, keystorePassword.toCharArray());
    }
}
```

#### 2.3 Perform Double Encryption

Now you can perform the encryption process.

```java
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.PublicKey;

public class DoubleEncryption {

    public static byte[] encryptWithPublicKey(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] encryptWithSymmetricKey(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
        String keystoreFile = "serverKeystore.jks";
        String keystorePassword = "password";
        String publicKeyAlias = "serverKeyPair";
        String secretKeyAlias = "clientSecretKey";

        // Load the server's public key
        PublicKey publicKey = PublicKeyLoader.loadPublicKey(keystoreFile, publicKeyAlias, keystorePassword);

        // Load the client's private key (symmetric key)
        SecretKey secretKey = SecretKeyLoader.loadSecretKey(keystoreFile, secretKeyAlias, keystorePassword);

        String data = "SensitiveData";
        byte[] encryptedData = encryptWithPublicKey(data.getBytes(), publicKey);
        encryptedData = encryptWithSymmetricKey(encryptedData, secretKey);

        System.out.println("Double encrypted data: " + new String(encryptedData));
    }
}
```

---

### Step 3: Decryption Process

For decryption, you'll need to reverse the process: first decrypt with the client's symmetric key and then with the server's private key (which the server has).