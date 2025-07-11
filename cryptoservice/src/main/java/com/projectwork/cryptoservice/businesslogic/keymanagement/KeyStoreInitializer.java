package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;

/**
 * KeyStoreInitializer is responsible for initializing the KeyStore with necessary keys.
 * It checks for the existence of specific keys and generates them if they are missing.
 */
@RequiredArgsConstructor
@Component
public class KeyStoreInitializer {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreInitializer.class);
    private static final int KEY_SIZE = 256;

    private final KeyStoreHelper keyStoreHelper;
    private final KeyStoreLoader keyStoreLoader;
    private final ErrorHandler errorHandler;

    /**
     * Initializes the KeyStore by checking for the existence of the JWT signing key and master key.
     * If they do not exist, it generates them.
     */
    @PostConstruct
    public final void initKeyStore() {
        LOGGER.info("Initializing KeyStore...");

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
        final KeyStore keystore = this.keyStoreLoader.load();

        try {
            final boolean missing = !keystore.containsAlias(alias);
            LOGGER.debug("Checked KeyStore for alias '{}': missing={}", alias, missing);
            return missing;
        } catch (final KeyStoreException exception) {
            final String context = String.format("While checking if alias '%s' exists in the keystore.", alias);
            throw this.errorHandler.handleError(
                    ErrorCode.KEYSTORE_NOT_INITIALIZED,
                    context,
                    exception
            );
        }
    }

    /**
     * Initializes the JWT signing key and stores it in the KeyStore.
     * If the key already exists, it skips the initialization.
     */
    private void initJwtSigningKey() {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
            LOGGER.debug("SecureRandom instance for JWT signing key initialized.");
        } catch (final NoSuchAlgorithmException exception) {
            throw this.errorHandler.handleError(
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
            throw this.errorHandler.handleError(
                    ErrorCode.JWT_KEYGEN_INIT_FAILED,
                    "While creating KeyGenerator for JWT signing key.",
                    exception
            );
        }

        try {
            keyGen.init(KEY_SIZE, secureRandom);
            LOGGER.debug("KeyGenerator initialized with secure random and key size {} for JWT signing key.", KEY_SIZE);
        } catch (final InvalidParameterException exception) {
            throw this.errorHandler.handleError(
                    ErrorCode.JWT_KEYGEN_INIT_PARAMS_INVALID,
                    "While initializing KeyGenerator with SecureRandom for JWT signing key.",
                    exception
            );
        }

        final SecretKey signingKey = keyGen.generateKey();
        LOGGER.debug("JWT signing key generated.");
        this.keyStoreHelper.storeKey("jwt-signing-key", signingKey);
    }

    /**
     * Initializes the master key and stores it in the KeyStore.
     * If the key already exists, it skips the initialization.
     */
    private void initMasterKey() {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
            LOGGER.debug("SecureRandom instance for master key initialized.");
        } catch (final NoSuchAlgorithmException exception) {
            throw this.errorHandler.handleError(
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
            throw this.errorHandler.handleError(
                    ErrorCode.MASTER_KEYGEN_INIT_FAILED,
                    "While creating KeyGenerator for master key.",
                    exception
            );
        }

        try {
            keyGen.init(KEY_SIZE, secureRandom);
            LOGGER.debug("KeyGenerator initialized with secure random and key size {} for master key.", KEY_SIZE);
        } catch (final InvalidParameterException exception) {
            throw this.errorHandler.handleError(
                    ErrorCode.MASTER_KEYGEN_PARAMS_INVALID,
                    "While initializing KeyGenerator with SecureRandom for master key.",
                    exception
            );
        }

        final SecretKey masterKey = keyGen.generateKey();
        LOGGER.debug("Master key generated.");
        this.keyStoreHelper.storeKey("master-key", masterKey);
    }
}
