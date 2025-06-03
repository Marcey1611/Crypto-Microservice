package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.io.*;
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

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

//TODO Refactor -> to long, methods to long and complex extend with helper classes or split in separate classes
/**
 * KeyStoreHelper is a utility class for managing cryptographic keys in a secure manner.
 * SecureCodingPractices
 * - OWASP [102] Master secret (KeyStore) protection
 * - OWASP [106] Centralized key storage and retrieval logic (KeyStore as secure container)
 * - OWASP [133] Stored keys are encrypted (with master key wrapping)
 * - OWASP [194] Carefully handle sensitive data (keystore password), wiping char arrays after use
 * - OWASP [199] Resources (File streams) properly closed using try-with-resources
 */
@Component
public class KeyStoreHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreHelper.class);

    private static final String KEYSTORE_PATH = System.getenv("KEYSTORE_PATH");

    /**
     * Stores a client key in the keystore under the specified alias.
     * 
     * @param alias The alias under which the key should be stored in the keystore.
     * @param key The SecretKey to be stored in the keystore.
     * @throws InternalServerErrorException An exception is thrown if there is an error during the key storage process.
     * - OWASP [102] Protect master secrets (Master Key retrieved securely).
     * - OWASP [103] Cryptographic modules fail securely (exception handling during cipher init/wrap).
     * - OWASP [106] Key management - proper wrapping of client keys with master key.
     * - OWASP [194] Passwords cleared from memory after use (Arrays.fill).
     */
    public final void storeKey(final String alias, final SecretKey key) {
        final KeyStore keystore = this.loadKeyStore();

        final String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();

        final SecretKey masterKey;
        try {
            masterKey = (SecretKey) keystore.getKey("master-key", passwordChars);
            
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_KEY_ACCESS_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While trying to retrieve the master key from keystore to encrypt and store a new client key.");
            errorDetailBuilder.withLogMsgFormatted("master-key");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
        if (null == masterKey) {
            final ErrorCode errorCode = ErrorCode.MASTER_KEY_MISSING;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While trying to get master key from keystore to encrypt a new client key and store it to the keystore.");
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
            final ErrorCode errorCode = ErrorCode.AES_CIPHER_INSTANCE_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While preparing AES cipher to encrypt the client key using the master key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
        
        try {
            cipher.init(Cipher.WRAP_MODE, masterKey);
        } catch (final InvalidKeyException | UnsupportedOperationException | InvalidParameterException exception) {
            final ErrorCode errorCode = ErrorCode.AES_CIPHER_INIT_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While initializing AES cipher in WRAP_MODE using the master key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
        
        final byte[] encryptedKey;
        try {
            encryptedKey = cipher.wrap(key);
        } catch (final IllegalStateException | IllegalBlockSizeException | InvalidKeyException | UnsupportedOperationException exception) {
            final ErrorCode errorCode = ErrorCode.AES_KEY_WRAP_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While wrapping the client key using AES and the initialized cipher.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }

        final SecretKeySpec encryptedKeySpec = new SecretKeySpec(encryptedKey, "AES");
        final SecretKeyEntry keyEntry = new SecretKeyEntry(encryptedKeySpec);
        final ProtectionParameter protection = new PasswordProtection(passwordChars);

        try {
            keystore.setEntry(alias, keyEntry, protection);
        } catch (final KeyStoreException exception) {
            final ErrorCode errorCode = ErrorCode.SETTING_KEYSTORE_ENTRY_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format(
                    "While trying to store encrypted client key with alias '%s' in keystore.",
                    alias
            );
            errorDetailBuilder.withContext(context);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);

        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [199]
        }

        this.saveKeyStore(keystore); // eigene Methode mit eigenem ErrorCode
    }

    /**
     * 
     * @return KeyStore instance loaded from the keystore file.
     * @throws InternalServerErrorException if there is an error loading the keystore.
     * 
     * SecureCodingPractices
     * - OWASP [102] Master secret (KeyStore) protection
     * - OWASP [194] Carefully handle sensitive data (keystore password), wiping char arrays after use
     * - OWASP [199] Resources (File streams) properly closed using try-with-resources
     */
    public final KeyStore loadKeyStore() {
        final KeyStore keystore;
        try {
            keystore = KeyStore.getInstance("PKCS12");
        } catch (final KeyStoreException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_TYPE_UNSUPPORTED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While creating keystore instance for loading the keystore from file.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
    
        final File keystoreFile = new File(KEYSTORE_PATH);
        final String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();

        final String absolutePath = keystoreFile.getAbsolutePath();
        try (final FileInputStream fis = new FileInputStream(absolutePath)) {
            try {
                keystore.load(fis, passwordChars);
            } catch (final IOException | NoSuchAlgorithmException | CertificateException exception) {
                final ErrorCode errorCode = ErrorCode.KEYSTORE_LOADING_FAILED;
                final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
                errorDetailBuilder.withContext("While loading keystore data from file into memory.");
                errorDetailBuilder.withException(exception);
                final ErrorDetail errorDetail = errorDetailBuilder.build();
                throw new InternalServerErrorException(errorDetail);
            }
            return keystore;
        } catch (final IOException | SecurityException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_FILE_READ_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While opening keystore file for reading.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    /**
     * 
     * @param keystore The KeyStore instance to be saved to the keystore file.
     * @throws InternalServerErrorException if there is an error saving the keystore.
     * SecureCodingPractices
     * - OWASP [102] Ensure keystore is always stored securely
     * - OWASP [199]
     */
    public final void saveKeyStore(final KeyStore keystore) {
        final File keystoreFile = new File(KEYSTORE_PATH);
        final String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();

        final String absolutePath = keystoreFile.getAbsolutePath();
        try (final FileOutputStream fos = new FileOutputStream(absolutePath)) {
            try {
                keystore.store(fos, passwordChars);
            } catch (final KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException exception) {
                final ErrorCode errorCode = ErrorCode.KEYSTORE_SAVE_FAILED;
                final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
                errorDetailBuilder.withContext("While storing keystore data to file.");
                errorDetailBuilder.withException(exception);
                final ErrorDetail errorDetail = errorDetailBuilder.build();
                throw new InternalServerErrorException(errorDetail);
            }
        } catch (final IOException | SecurityException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_FILE_WRITE_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While opening keystore file for writing.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [199]
        }
    }

    /**
     * Retrieves a client key from the keystore, decrypting it using the master key.
     *
     * @param alias The alias of the client key to be retrieved.
     * @return The decrypted SecretKey associated with the specified alias.
     * @throws InternalServerErrorException if there is an error accessing or decrypting the key.
     * SecureCodingPractices
     * - OWASP [102] Master secret (KeyStore) protection
     * - OWASP [106] Centralized key storage and retrieval logic (KeyStore as secure container)
     * - OWASP [133] Stored keys are encrypted (with master key wrapping)
     * - OWASP [194] Carefully handle sensitive data (keystore password), wiping char arrays after use
     */
    public final SecretKey getClientKey(final String alias) {
        final KeyStore keystore = this.loadKeyStore();
        final String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();

        final SecretKey encryptedKey;
        try {
            encryptedKey = (SecretKey) keystore.getKey(alias, passwordChars);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_KEY_ACCESS_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format(
                    "While accessing encrypted client key for alias '%s' in keystore.",
                    alias
            );
            errorDetailBuilder.withContext(context);
            errorDetailBuilder.withLogMsgFormatted(alias);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }

        SecretKey masterKey;
        try {
            masterKey = (SecretKey) keystore.getKey("master-key", passwordChars);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_KEY_ACCESS_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While accessing master key from keystore to decrypt client key.");
            errorDetailBuilder.withLogMsgFormatted("master-key");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        } finally {
            Arrays.fill(passwordChars, '\0');
        }

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
            final ErrorCode errorCode = ErrorCode.AES_CIPHER_INSTANCE_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While preparing AES cipher for client key decryption.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }

        try {
            cipher.init(Cipher.UNWRAP_MODE, masterKey);
        } catch (final InvalidKeyException | UnsupportedOperationException | InvalidParameterException exception) {
            final ErrorCode errorCode = ErrorCode.AES_CIPHER_INIT_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While initializing AES cipher in UNWRAP_MODE to decrypt client key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }

        final SecretKey decryptedKey;
        try {
            final byte[] encryptedKeyEncoded = encryptedKey.getEncoded();
            decryptedKey = (SecretKey) cipher.unwrap(encryptedKeyEncoded, "AES", Cipher.SECRET_KEY);
        } catch (final IllegalStateException | NoSuchAlgorithmException | InvalidKeyException | UnsupportedOperationException exception) {
            final ErrorCode errorCode = ErrorCode.CLIENT_KEY_UNWRAP_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While unwrapping (decrypting) client key using master key and AES cipher.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
        return decryptedKey;
    }

    /**
     * Retrieves a key from the keystore by its alias.
     *
     * @param alias The alias of the key to be retrieved.
     * @return The SecretKey associated with the specified alias.
     * @throws InternalServerErrorException if there is an error accessing the key.
     * SecureCodingPractices
     * - OWASP [102] Master secret (KeyStore) protection
     * - OWASP [106] Centralized key storage and retrieval logic (KeyStore as secure container)
     * - OWASP [194] Carefully handle sensitive data (keystore password), wiping char arrays after use
     */
    public final SecretKey getKey(final String alias) {
        final KeyStore keystore = this.loadKeyStore();
        final String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        try {
            return (SecretKey) keystore.getKey(alias, passwordChars);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_KEY_ACCESS_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format(
                    "While accessing key with alias '%s' from keystore.",
                    alias
            );
            errorDetailBuilder.withContext(context);
            errorDetailBuilder.withLogMsgFormatted(alias);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);

        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [199]
        }
    }
}
