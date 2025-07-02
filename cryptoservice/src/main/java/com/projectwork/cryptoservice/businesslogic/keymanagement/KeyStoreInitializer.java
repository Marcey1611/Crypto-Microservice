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

//TODO maybe refactoring too complex (methods)
/**
 * KeyStoreInitializer is responsible for initializing the KeyStore with necessary keys
 * SecureCodingPractices
 * - OWASP [101] Crypto operations (key gen) on trusted server
 * - OWASP [104] Secure Random for all key generations
 * - OWASP [106] Key management initialization (ensures master and signing keys)
 */
@RequiredArgsConstructor
@Component
public class KeyStoreInitializer {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreInitializer.class);
    private static final int KEY_SIZE = 256;

    private final KeyStoreHelper keyStoreHelper;
    private final KeyStoreLoader keyStoreLoader;

    // OWASP [102] Ensuring master secrets (master-key & jwt-signing-key) are protected and initialized
    /**
     * Initializes the KeyStore with a JWT signing key and a master key if they do not already exist.
     * This method is called after the application context is initialized.
     * SecureCodingPractices:
     * - OWASP [101] Crypto operations (key gen) on trusted server
     * - OWASP [104] Secure Random for all key generations
     * - OWASP [106] Key management initialization (ensures master and signing keys)
     */
    @PostConstruct
    public final void initKeyStore() {
        if (this.checkContainsAlias("jwt-signing-key")) {
            //TODO Logging System.out.println("Keystore enthält keinen JWT-Signing-Key. Neuer Key wird generiert...");
            this.initJwtSigningKey();
            //TODO logging System.out.println("JWT-Signing-Key erfolgreich im Keystore gespeichert!");
        } else {
            //TODO logging System.out.println("JWT-Signing-Key bereits im Keystore vorhanden.");
        }
        
        if (this.checkContainsAlias("master-key")) {
            //TODO logging System.out.println("Keystore enthält keinen Master-Key. Neuer Key wird generiert...");
            this.initMasterKey();
            //TODO logging System.out.println("Master-Key erfolgreich im KeyStore gespeichert.");
        } else {
            //TODO logging System.out.println("Master-Key bereits im KeyStore vorhanden.");
        }
    }

    /**
     * Checks if the KeyStore contains an alias.
     *
     * @param alias the alias to check
     * @return true if the alias exists, false otherwise
     * SecureCodingPractices:
     * - OWASP [106] Key management initialization (ensures master and signing keys)
     */
    private boolean checkContainsAlias(final String alias) {
        final KeyStore keystore = this.keyStoreLoader.load();

        try {
            return !keystore.containsAlias(alias);
        } catch (final KeyStoreException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_NOT_INITIALIZED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format(
                    "While checking if alias '%s' exists in the keystore.",
                    alias
            );
            errorDetailBuilder.withContext(context);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
    }

    /**
     * Initializes the JWT signing key in the KeyStore.
     * 
     * @throws InternalServerErrorException if there is an error during key generation or storage
     * SecureCodingPractices:
     * - OWASP 104 Secure Random Number Generation: Key generation uses SecureRandom.getInstanceStrong() as cryptographical secure random source
     */
    private void initJwtSigningKey() {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException exception) {
            final ErrorCode errorCode = ErrorCode.JWT_SECURE_RANDOM_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While creating SecureRandom instance for generating JWT signing key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
    
        final KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("HmacSHA256");
        } catch (final NoSuchAlgorithmException exception) {
            final ErrorCode errorCode = ErrorCode.JWT_KEYGEN_INIT_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While creating KeyGenerator for JWT signing key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
    
        try {
            keyGen.init(KEY_SIZE, secureRandom);
        } catch (final InvalidParameterException exception) {
            final ErrorCode errorCode = ErrorCode.JWT_KEYGEN_INIT_PARAMS_INVALID;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While initializing KeyGenerator with SecureRandom for JWT signing key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
    
        final SecretKey signingKey = keyGen.generateKey();
        this.keyStoreHelper.storeKey("jwt-signing-key", signingKey); // Fehlerbehandlung findet dort statt
    }
    

    /**
     * 
     * @throws InternalServerErrorException if there is an error during master key generation or storage
     * SecureCodingPractices:
     * - OWASP 104 Secure Random Number Generation: Key generation uses SecureRandom.getInstanceStrong() as cryptographical secure random source
     */
    private void initMasterKey() {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException exception) {
            final ErrorCode errorCode = ErrorCode.MASTER_KEY_SECURE_RANDOM_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While creating SecureRandom for master key generation.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
    
        final KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (final NoSuchAlgorithmException exception) {
            final ErrorCode errorCode = ErrorCode.MASTER_KEYGEN_INIT_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While creating KeyGenerator for master key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
    
        try {
            keyGen.init(KEY_SIZE, secureRandom);
        } catch (final InvalidParameterException exception) {
            final ErrorCode errorCode = ErrorCode.MASTER_KEYGEN_PARAMS_INVALID;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While initializing KeyGenerator with SecureRandom for master key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
    
        final SecretKey masterKey = keyGen.generateKey();
        this.keyStoreHelper.storeKey("master-key", masterKey); // eigene Fehlerbehandlung dort
    }
    
}
