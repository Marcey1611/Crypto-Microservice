package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.security.*;

/**
 * KeyStoreInitializer is responsible for initializing the KeyStore with necessary keys.
 * It checks for the existence of specific keys and generates them if they are missing.
 *
 * SCPs:
 * - [80] Deny all access if the application cannot access its security configuration information
 * - [114] Logging controls should support both success and failure of specified security events
 */
@RequiredArgsConstructor
@Component
public class KeyStoreInitializer {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreInitializer.class);
    private static final int KEY_SIZE = 256;

    private final KeyStoreHelper keyStoreHelper;
    private final KeyStoreLoader keyStoreLoader;
    private final ErrorHandler errorHandler;

    @Value("${master.keystore.path}")
    private String masterKeystorePath;

    @Value("${master.keystore.password}")
    private String masterKeystorePassword;

    @Value("${client.keystore.path}")
    private String clientKeystorePath;

    @Value("${client.keystore.password}")
    private String clientKeystorePassword;

    /**
     * Initializes the KeyStore by checking for the existence of the JWT signing key and master key.
     * If they do not exist, it generates them.
     */
    @PostConstruct
    public final void initKeyStore() {
        LOGGER.info("Initializing KeyStore...");

        this.validateFileExists(this.masterKeystorePath);
        this.validateFileExists(this.clientKeystorePath);

        final KeyStore masterKeystore = this.validateAccessToKeyStore(this.masterKeystorePath, this.masterKeystorePassword);
        this.validateMasterKeyStoreNotEmpty(masterKeystore, this.masterKeystorePath);
        this.validateAccessToKeyStore(this.clientKeystorePath, this.clientKeystorePassword);

        if (this.checkContainsAlias("jwt-signing-key")) {
            LOGGER.info("JWT signing key not found in KeyStore – generating new one...");
            this.initJwtSigningKey();
            LOGGER.info("JWT signing key successfully initialized.");
        } else {
            LOGGER.info("JWT signing key already exists – skipping initialization.");
        }

        if (this.checkContainsAlias("master-key")) {
            LOGGER.info("Master key not found in KeyStore – generating new one...");
            this.initMasterKey();
            LOGGER.info("Master key successfully initialized.");
        } else {
            LOGGER.info("Master key already exists – skipping initialization.");
        }
    }

    /**
     * Checks if the KeyStore contains a specific alias.
     *
     * @param alias the alias to check
     * @return true if the alias is missing, false otherwise
     */
    private boolean checkContainsAlias(final String alias) {
        final KeyStore keystore = this.keyStoreLoader.load(this.masterKeystorePath, this.masterKeystorePassword);

        try {
            final boolean missing = !keystore.containsAlias(alias);
            LOGGER.debug("Checked KeyStore for given alias.");
            return missing;
        } catch (final KeyStoreException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.KEYSTORE_NOT_INITIALIZED,
                    "While checking if alias exists in the keystore.",
                    exception
            );
        }
    }

    /**
     * Initializes the JWT signing key and stores it in the KeyStore.
     * If the key already exists, it skips the initialization.
     *
     * SCP104
     */
    private void initJwtSigningKey() {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
            LOGGER.debug("SecureRandom instance for JWT signing key initialized.");
        } catch (final NoSuchAlgorithmException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.JWT_SECURE_RANDOM_FAILED,
                    "While creating SecureRandom instance for generating JWT signing key.",
                    exception
            );
        }

        final KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("HmacSHA256");
            LOGGER.debug("KeyGenerator for JWT signing key initialized with HmacSHA256.");
        } catch (final NoSuchAlgorithmException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.JWT_KEYGEN_INIT_FAILED,
                    "While creating KeyGenerator for JWT signing key.",
                    exception
            );
        }

        try {
            keyGen.init(KEY_SIZE, secureRandom);
            LOGGER.debug("KeyGenerator initialized with secure random and key size {} for JWT signing key.", KEY_SIZE);
        } catch (final InvalidParameterException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.JWT_KEYGEN_INIT_PARAMS_INVALID,
                    "While initializing KeyGenerator with SecureRandom for JWT signing key.",
                    exception
            );
        }

        final SecretKey signingKey = keyGen.generateKey();
        final byte[] signingKeyBytes = signingKey.getEncoded();
        LOGGER.debug("JWT signing key generated.");
        this.keyStoreHelper.storeKey("jwt-signing-key", signingKeyBytes, this.masterKeystorePath, this.masterKeystorePassword);
    }

    /**
     * Initializes the master key and stores it in the KeyStore.
     * If the key already exists, it skips the initialization.
     *
     * SCP104
     */
    private void initMasterKey() {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
            LOGGER.debug("SecureRandom instance for master key initialized.");
        } catch (final NoSuchAlgorithmException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.MASTER_KEY_SECURE_RANDOM_FAILED,
                    "While creating SecureRandom for master key generation.",
                    exception
            );
        }

        final KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
            LOGGER.debug("KeyGenerator for master key initialized with AES.");
        } catch (final NoSuchAlgorithmException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.MASTER_KEYGEN_INIT_FAILED,
                    "While creating KeyGenerator for master key.",
                    exception
            );
        }

        try {
            keyGen.init(KEY_SIZE, secureRandom);
            LOGGER.debug("KeyGenerator initialized with secure random and key size {} for master key.", KEY_SIZE);
        } catch (final InvalidParameterException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.MASTER_KEYGEN_PARAMS_INVALID,
                    "While initializing KeyGenerator with SecureRandom for master key.",
                    exception
            );
        }

        final SecretKey masterKey = keyGen.generateKey();
        final byte[] masterKeyBytes = masterKey.getEncoded();
        LOGGER.debug("Master key generated.");
        this.keyStoreHelper.storeKey("master-key", masterKeyBytes, this.masterKeystorePath, this.masterKeystorePassword);
    }

    private void validateFileExists(final String path) {
        final File file = new File(path);
        if (!file.exists()) {
            LOGGER.error("KeyStore file does not exist. Application will terminate!");
            System.exit(1);
        }
    }

    /**
     * Validates access to the KeyStore by loading it from the specified path and password.
     * If the KeyStore cannot be loaded, it logs an error and terminates the application.
     *
     * @param path     the path to the KeyStore
     * @param password the password for the KeyStore
     * @return the loaded KeyStore
     */
    private KeyStore validateAccessToKeyStore(final String path, final String password) {
        final File file = new File(path);
        if (!file.exists()) {
            throw this.errorHandler.handleBusinessError(
                    "KeyStore file does not exist.",
                    ErrorCode.KEYSTORE_ACCESS_FAILED
            );
        }

        try {
            return this.keyStoreLoader.load(path, password);
        } catch (final Exception exception) {
            LOGGER.error("Failed to load KeyStore. Application will terminate!");
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.KEYSTORE_ACCESS_FAILED,
                    "While loading KeyStore.",
                    exception
            );
        }
    }

    /**
     * Validates that the master KeyStore is not empty.
     * If it is empty, it logs an error and terminates the application.
     *
     * @param keystore the KeyStore to validate
     * @param path     the path of the KeyStore
     */
    private void validateMasterKeyStoreNotEmpty(final KeyStore keystore, final String path) {
        try {
            if (keystore.size() == 0) {
                LOGGER.error("KeyStore is empty. Application will terminate!");
                System.exit(1);
            }
        } catch (final KeyStoreException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.MASTER_KEYSTORE_INVALID_OR_CORRUPTED,
                    "While checking KeyStore size.",
                    exception
            );
        }
    }
}
