package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
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

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

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
        final KeyStore keystore = loadKeyStore();

        String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        keystorePassword = null;

        final SecretKey masterKey;
        try {
            masterKey = (SecretKey) keystore.getKey("master-key", passwordChars);
            if (masterKey == null) {
                throw new InternalServerErrorException(
                    ErrorCode.MASTER_KEY_MISSING.builder().build()
                );
            }
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_ACCESS_FAILED.builder()
                    .withLogMsgFormatted("master-key", exception.toString())
                    .build()
            );
        }

        final byte[] encryptedKey;
        try {
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.WRAP_MODE, masterKey);
            encryptedKey = cipher.wrap(key);
        } catch (final GeneralSecurityException exception) {
            throw new InternalServerErrorException(
                ErrorCode.CLIENT_KEY_ENCRYPTION_FAILED.builder()
                    .withLogMsgFormatted(alias, exception.toString())
                    .build()
            );
        }

        try {
            final SecretKeySpec encryptedKeySpec = new SecretKeySpec(encryptedKey, "AES");
            final SecretKeyEntry keyEntry = new SecretKeyEntry(encryptedKeySpec);
            final ProtectionParameter protection = new PasswordProtection(passwordChars);

            try {
                keystore.setEntry(alias, keyEntry, protection);
            } catch (final KeyStoreException e) {
                throw new InternalServerErrorException(
                    ErrorCode.KEYSTORE_ENTRY_FAILED.builder()
                        .withLogMsgFormatted(alias, e.toString())
                        .build()
                );
            }

            saveKeyStore(keystore); // eigene Methode mit eigenem ErrorCode
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [199]
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
        final KeyStore keystore;
        try {
            keystore = KeyStore.getInstance("PKCS12");
        } catch (final KeyStoreException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_INIT_FAILED.builder()
                    .withLogMsgFormatted(exception.toString())
                    .build()
            );
        }
    
        final File keystoreFile = new File(KEYSTORE_PATH);
        String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        keystorePassword = null;
    
        try (final FileInputStream fis = new FileInputStream(keystoreFile.getAbsolutePath())) {
            keystore.load(fis, passwordChars);
            return keystore;
        } catch (final NoSuchAlgorithmException | CertificateException | IOException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_LOAD_FAILED.builder()
                    .withLogMsgFormatted(keystoreFile.getAbsolutePath(), exception.toString())
                    .build()
            );
    
        } finally {
            Arrays.fill(passwordChars, '\0'); // sensible Daten nullen
        }
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
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_SAVE_FAILED.builder()
                    .withLogMsgFormatted(keystoreFile.getAbsolutePath(), exception.toString())
                    .build()
            );
    
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP Empfehlung [199]
        }
    }
    
    public SecretKey getClientKey(final String alias) {
        final KeyStore keystore = loadKeyStore();
        String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        keystorePassword = null;

        SecretKey encryptedKey;
        SecretKey masterKey;
        try {
            encryptedKey = (SecretKey) keystore.getKey(alias, passwordChars);
            masterKey = (SecretKey) keystore.getKey("master-key", passwordChars);
        } catch (final UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_ACCESS_FAILED.builder()
                    .withLogMsgFormatted(alias, exception.toString())
                    .build()
            );
        }

        try {
            final Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.UNWRAP_MODE, masterKey);
            final SecretKey decryptedKey = (SecretKey) cipher.unwrap(
                encryptedKey.getEncoded(), "AES", Cipher.SECRET_KEY
            );
            return decryptedKey;
        } catch (final NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException exception) {
            throw new InternalServerErrorException(
                ErrorCode.CLIENT_KEY_DECRYPTION_FAILED.builder()
                    .withLogMsgFormatted(alias, exception.toString())
                    .build()
            );
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    public SecretKey getKey(final String alias) {
        final KeyStore keystore = loadKeyStore();
        String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        keystorePassword = null;

        try {
            return (SecretKey) keystore.getKey(alias, passwordChars);
        } catch (final UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException exception) {
            throw new InternalServerErrorException(ErrorCode.KEYSTORE_ACCESS_FAILED.builder()
                .withLogMsgFormatted(alias, exception.toString())
                .build()
            );
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [199]
        }
    }
}
