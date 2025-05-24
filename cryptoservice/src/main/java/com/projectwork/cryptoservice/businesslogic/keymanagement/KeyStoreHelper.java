package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
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
import javax.crypto.IllegalBlockSizeException;
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
            
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_KEY_ACCESS_FAILED.builder()
                .withContext("While trying to retrieve the master key from keystore to encrypt and store a new client key.")
                .withLogMsgFormatted("master-key")
                .withException(exception)
                .build()
            );
        }
        if (masterKey == null) {
            throw new InternalServerErrorException(
                ErrorCode.MASTER_KEY_MISSING.builder()
                    .withContext("While trying to get master key from keystore to encrypt a new client key and store it to the keystore.")
                    .build()
            );
        }

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
            throw new InternalServerErrorException(
                ErrorCode.AES_CIPHER_INSTANCE_FAILED.builder()
                    .withContext("While preparing AES cipher to encrypt the client key using the master key.")
                    .withException(exception)
                    .build()
            );
        }
        
        try {
            cipher.init(Cipher.WRAP_MODE, masterKey);
        } catch (final InvalidKeyException | UnsupportedOperationException | InvalidParameterException exception) {
            throw new InternalServerErrorException(
                ErrorCode.AES_CIPHER_INIT_FAILED.builder()
                    .withContext("While initializing AES cipher in WRAP_MODE using the master key.")
                    .withException(exception)
                    .build()
            );
        }
        
        final byte[] encryptedKey;
        try {
            encryptedKey = cipher.wrap(key);
        } catch (final IllegalStateException | IllegalBlockSizeException | InvalidKeyException | UnsupportedOperationException exception) {
            throw new InternalServerErrorException(
                ErrorCode.AES_KEY_WRAP_FAILED.builder()
                    .withContext("While wrapping the client key using AES and the initialized cipher.")
                    .withException(exception)
                    .build()
            );
        }

        final SecretKeySpec encryptedKeySpec = new SecretKeySpec(encryptedKey, "AES");
        final SecretKeyEntry keyEntry = new SecretKeyEntry(encryptedKeySpec);
        final ProtectionParameter protection = new PasswordProtection(passwordChars);

        try {
            keystore.setEntry(alias, keyEntry, protection);
        } catch (final KeyStoreException exception) {
            throw new InternalServerErrorException(
                ErrorCode.SETTING_KEYSTORE_ENTRY_FAILED.builder()
                    .withContext(String.format("While trying to store encrypted client key with alias '%s' in keystore.", alias))
                    .withException(exception)
                    .build()
            );
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [199]
        }
        
        saveKeyStore(keystore); // eigene Methode mit eigenem ErrorCode
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
                ErrorCode.KEYSTORE_TYPE_UNSUPPORTED.builder()
                    .withContext("While creating keystore instance for loading the keystore from file.")
                    .withException(exception)
                    .build()
            );
        }
    
        final File keystoreFile = new File(KEYSTORE_PATH);
        String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        keystorePassword = null;
    
        try (FileInputStream fis = new FileInputStream(keystoreFile.getAbsolutePath())) {
            try {
                keystore.load(fis, passwordChars);
            } catch (final IOException | NoSuchAlgorithmException | CertificateException exception) {
                throw new InternalServerErrorException(
                    ErrorCode.KEYSTORE_LOADING_FAILED.builder()
                        .withContext("While loading keystore data from file into memory.")
                        .withException(exception)
                        .build()
                );
            }
            return keystore;
        } catch (final IOException | SecurityException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_FILE_READ_FAILED.builder()
                    .withContext("While opening keystore file for reading.")
                    .withException(exception)
                    .build()
            );
        } finally {
            Arrays.fill(passwordChars, '\0');
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
    
        try (FileOutputStream fos = new FileOutputStream(keystoreFile.getAbsolutePath())) {
            try {
                keystore.store(fos, passwordChars);
            } catch (final KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException exception) {
                throw new InternalServerErrorException(
                    ErrorCode.KEYSTORE_SAVE_FAILED.builder()
                        .withContext("While storing keystore data to file.")
                        .withException(exception)
                        .build()
                );
            }
        } catch (final IOException | SecurityException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_FILE_WRITE_FAILED.builder()
                    .withContext("While opening keystore file for writing.")
                    .withException(exception)
                    .build()
            );
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [199]
        }
    }
    
    public SecretKey getClientKey(final String alias) {
        final KeyStore keystore = loadKeyStore();
        String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        keystorePassword = null;

        SecretKey encryptedKey;
        try {
            encryptedKey = (SecretKey) keystore.getKey(alias, passwordChars);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_KEY_ACCESS_FAILED.builder()
                    .withContext(String.format("While accessing encrypted client key for alias '%s' in keystore.", alias))
                    .withLogMsgFormatted(alias)
                    .withException(exception)
                    .build()
            );
        }

        SecretKey masterKey;
        try {
            masterKey = (SecretKey) keystore.getKey("master-key", passwordChars);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_KEY_ACCESS_FAILED.builder()
                    .withContext("While accessing master key from keystore to decrypt client key.")
                    .withLogMsgFormatted("master-key")
                    .withException(exception)
                    .build()
            );
        } finally {
            Arrays.fill(passwordChars, '\0');
        }

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
            throw new InternalServerErrorException(
                ErrorCode.AES_CIPHER_INSTANCE_FAILED.builder()
                    .withContext("While preparing AES cipher for client key decryption.")
                    .withException(exception)
                    .build()
            );
        }

        try {
            cipher.init(Cipher.UNWRAP_MODE, masterKey);
        } catch (final InvalidKeyException | UnsupportedOperationException | InvalidParameterException exception) {
            throw new InternalServerErrorException(
                ErrorCode.AES_CIPHER_INIT_FAILED.builder()
                    .withContext("While initializing AES cipher in UNWRAP_MODE to decrypt client key.")
                    .withException(exception)
                    .build()
            );
        }

        final SecretKey decryptedKey;
        try {
            decryptedKey = (SecretKey) cipher.unwrap(encryptedKey.getEncoded(), "AES", Cipher.SECRET_KEY);
        } catch (final IllegalStateException | NoSuchAlgorithmException | InvalidKeyException | UnsupportedOperationException exception) {
            throw new InternalServerErrorException(
                ErrorCode.CLIENT_KEY_UNWRAP_FAILED.builder()
                    .withContext("While unwrapping (decrypting) client key using master key and AES cipher.")
                    .withException(exception)
                    .build()
            );
        }
        return decryptedKey;
            
    }

    public SecretKey getKey(final String alias) {
        final KeyStore keystore = loadKeyStore();
        String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        keystorePassword = null;
        try {
            return (SecretKey) keystore.getKey(alias, passwordChars);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_KEY_ACCESS_FAILED.builder()
                    .withContext(String.format("While accessing key with alias '%s' from keystore.", alias))
                    .withLogMsgFormatted(alias)
                    .withException(exception)
                    .build()
            );
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [199]
        }
    }
}
