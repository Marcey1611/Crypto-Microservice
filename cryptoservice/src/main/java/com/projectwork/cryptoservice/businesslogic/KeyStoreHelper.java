package com.projectwork.cryptoservice.businesslogic;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.util.Arrays;
import java.util.Enumeration;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

@Component
public class KeyStoreHelper {
    private static final String KEYSTORE_PATH = "/keystores/keystore.jks";

    @Value("${keystore.password}")
    private String keystorePassword;

    public KeyStore loadKeyStore() throws Exception {
        final KeyStore keystore = KeyStore.getInstance("PKCS12"); 
        final File keystoreFile = new File(getClass().getResource(KEYSTORE_PATH).getFile());
        final char[] passwordChars = keystorePassword.toCharArray();
        try (final FileInputStream fis = new FileInputStream(keystoreFile.getAbsolutePath())) { 
            keystore.load(fis, passwordChars);
        } finally {
            Arrays.fill(passwordChars, '\0'); //Passwort aus speicher löschen ist nur solange drin wie nötig
        }
        return keystore;
    }

    public void saveKeyStore(KeyStore keystore) throws Exception {
        final File keystoreFile = new File(getClass().getResource(KEYSTORE_PATH).getFile());
        final char[] passwordChars = keystorePassword.toCharArray();
        try (FileOutputStream fos = new FileOutputStream(keystoreFile.getAbsolutePath())) {
            keystore.store(fos, passwordChars);
        } finally {
            Arrays.fill(passwordChars, '\0'); //Passwort aus speicher löschen ist nur solange drin wie nötig
        }
    }

    public void storeKey(String alias, SecretKey key) throws Exception {
        try {
            final KeyStore keystore = loadKeyStore();

            String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
            final char[] passwordChars = keystorePassword.toCharArray();
            keystorePassword = null;
            
            final SecretKey masterKey = (SecretKey) keystore.getKey("master-key", passwordChars);
            if (masterKey == null) {
                throw new RuntimeException("Master Key nicht gefunden!");
            }
            
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.WRAP_MODE, masterKey);
            final byte[] encryptedKey = cipher.wrap(key);
            final SecretKeySpec encryptedKeySpec = new SecretKeySpec(encryptedKey, "AES");
            
            final SecretKeyEntry keyEntry = new SecretKeyEntry(encryptedKeySpec);
            final ProtectionParameter protection = new PasswordProtection(passwordChars);
            keystore.setEntry(alias, keyEntry, protection);
            saveKeyStore(keystore);
            Arrays.fill(passwordChars, '\0');

            final Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                System.out.println(aliases.nextElement());
            }
        } catch (Exception e) {
            System.out.println("Fehler beim speichern des Keys: " + e);
        }
    }

    public SecretKey getKey(String alias) throws Exception {
        final KeyStore keystore = loadKeyStore();
        return (SecretKey) keystore.getKey(alias, keystorePassword.toCharArray());
    }
}
