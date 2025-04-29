package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

/**
 * 
 * SecureCodingPRactices
 * - OWASP [102] Master secret (KeyStore) protection
 * - OWASP [106] Centralized key storage and retrieval logic (KeyStore as secure container)
 * - OWASP [133] Stored keys are encrypted (with master key wrapping)
 * - OWASP [194] Carefully handle sensitive data (keystore password), wiping char arrays after use
 * - OWASP [199] Resources (File streams) properly closed using try-with-resources
 */
@Component
public class KeyStoreHelper {
    private static final String KEYSTORE_PATH = System.getenv("KEYSTORE_PATH");

    /**
     * 
     * @param alias
     * @param key
     * @throws Exception
     * 
     * - OWASP [102] Protect master secrets (Master Key retrieved securely).
     * - OWASP [103] Cryptographic modules fail securely (exception handling during cipher init/wrap).
     * - OWASP [106] Key management - proper wrapping of client keys with master key.
     * - OWASP [194] Passwords cleared from memory after use (Arrays.fill).
     */
    public void storeKey(final String alias, final SecretKey key) {
        try {
            final KeyStore keystore = loadKeyStore();

            String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
            final char[] passwordChars = keystorePassword.toCharArray();
            keystorePassword = null;

            final SecretKey masterKey = (SecretKey) keystore.getKey("master-key", passwordChars);
            if (masterKey == null) {
                throw new RuntimeException("Master Key nicht gefunden!"); // OWASP [103] Fail securely if master key is missing
            }
            
            // OWASP [104] Using strong AES wrapping for client key protection
            // OWASP [133] Stored keys are encrypted (with master key wrapping)
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.WRAP_MODE, masterKey);
            final byte[] encryptedKey = cipher.wrap(key);
            final SecretKeySpec encryptedKeySpec = new SecretKeySpec(encryptedKey, "AES");
            
            final SecretKeyEntry keyEntry = new SecretKeyEntry(encryptedKeySpec);
            final ProtectionParameter protection = new PasswordProtection(passwordChars);
            keystore.setEntry(alias, keyEntry, protection);
            saveKeyStore(keystore);
            Arrays.fill(passwordChars, '\0'); // OWASP [199]

            final Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                System.out.println(aliases.nextElement());
            }
        } catch (final Exception exception) {
            System.out.println("Fehler beim speichern des Keys: " + exception);
        }
    }

    /**
     * 
     * @return
     * @throws Exception
     * 
     * SecureCodingPractices
     * - OWASP [102] Master secret (KeyStore) protection
     * - OWASP [194] Carefully handle sensitive data (keystore password), wiping char arrays after use
     * - OWASP [199] Resources (File streams) properly closed using try-with-resources
     */
    public KeyStore loadKeyStore() {
        KeyStore keystore = null;
        try {
            keystore = KeyStore.getInstance("PKCS12");
        } catch (final KeyStoreException exception) {
            // TODO Auto-generated catch block
            exception.printStackTrace();
        } 
        final File keystoreFile = new File(KEYSTORE_PATH);
        
        String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        keystorePassword = null;
        
        try (final FileInputStream fis = new FileInputStream(keystoreFile.getAbsolutePath())) { 
            keystore.load(fis, passwordChars); // OWASP [102] Use password protection for keystore access
        } catch (final NoSuchAlgorithmException | CertificateException | IOException exception) {
            // TODO Auto-generated catch block
            exception.printStackTrace();
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [199] Clear sensitive data from memory after use
        }
        return keystore;
    }

    /**
     * 
     * @param keystore
     * @throws Exception
     * 
     * SecureCodingPractices
     * - OWASP [102] Ensure keystore is always stored securely
     * - OWASP [199]
     */
    public void saveKeyStore(final KeyStore keystore) {
        final File keystoreFile = new File(KEYSTORE_PATH);

        String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        keystorePassword = null;

        try (final FileOutputStream fos = new FileOutputStream(keystoreFile.getAbsolutePath())) {
            keystore.store(fos, passwordChars);
        } catch (final KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException exception) {
            // TODO Auto-generated catch block
            exception.printStackTrace();
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [199]
        }
    }

    public SecretKey getClientKey(final String alias) {
        final KeyStore keystore = loadKeyStore();

        String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        keystorePassword = null;

        SecretKey decryptedKey = null;
        try {
            final SecretKey encryptedKey = (SecretKey) keystore.getKey(alias, passwordChars);
            final SecretKey masterKey = (SecretKey) keystore.getKey("master-key", passwordChars);
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.UNWRAP_MODE, masterKey);
            decryptedKey = (SecretKey) cipher.unwrap(encryptedKey.getEncoded(), "AES", Cipher.SECRET_KEY);
        } catch (final UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | 
                NoSuchPaddingException | InvalidKeyException exception) {
            // TODO Auto-generated catch block
            exception.printStackTrace();
        }
        
        Arrays.fill(passwordChars, '\0'); // OWASP [199]
        return decryptedKey;
    }

    public SecretKey getKey(final String alias) {
        final KeyStore keystore = loadKeyStore();

        String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        keystorePassword = null;

        SecretKey key = null;
        try {
            key = (SecretKey) keystore.getKey(alias, passwordChars);
        } catch (final UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException exception) {
            // TODO Auto-generated catch block
            exception.printStackTrace();
        }
        Arrays.fill(passwordChars, '\0'); // OWASP [199]
        return key;
    }
}
