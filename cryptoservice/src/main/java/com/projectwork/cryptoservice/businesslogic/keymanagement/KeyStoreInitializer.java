package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;

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
            final ErrorCode errorCode = ErrorCode.KEYSTORE_NOT_INITIALIZED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format("While checking if alias '%s' exists in the keystore.", alias);
            errorDetailBuilder.withContext(context);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
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
            final ErrorCode errorCode = ErrorCode.JWT_SECURE_RANDOM_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While creating SecureRandom instance for generating JWT signing key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        final KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("HmacSHA256");
            LOGGER.debug("KeyGenerator for JWT signing key initialized with HmacSHA256.");
        } catch (final NoSuchAlgorithmException exception) {
            final ErrorCode errorCode = ErrorCode.JWT_KEYGEN_INIT_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While creating KeyGenerator for JWT signing key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        try {
            keyGen.init(KEY_SIZE, secureRandom);
            LOGGER.debug("KeyGenerator initialized with secure random and key size {} for JWT signing key.", KEY_SIZE);
        } catch (final InvalidParameterException exception) {
            final ErrorCode errorCode = ErrorCode.JWT_KEYGEN_INIT_PARAMS_INVALID;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While initializing KeyGenerator with SecureRandom for JWT signing key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
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
            final ErrorCode errorCode = ErrorCode.MASTER_KEY_SECURE_RANDOM_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While creating SecureRandom for master key generation.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        final KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
            LOGGER.debug("KeyGenerator for master key initialized with AES.");
        } catch (final NoSuchAlgorithmException exception) {
            final ErrorCode errorCode = ErrorCode.MASTER_KEYGEN_INIT_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While creating KeyGenerator for master key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        try {
            keyGen.init(KEY_SIZE, secureRandom);
            LOGGER.debug("KeyGenerator initialized with secure random and key size {} for master key.", KEY_SIZE);
        } catch (final InvalidParameterException exception) {
            final ErrorCode errorCode = ErrorCode.MASTER_KEYGEN_PARAMS_INVALID;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While initializing KeyGenerator with SecureRandom for master key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        final SecretKey masterKey = keyGen.generateKey();
        LOGGER.debug("Master key generated.");
        this.keyStoreHelper.storeKey("master-key", masterKey);
    }
}
