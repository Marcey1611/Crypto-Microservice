package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.entity.factory.ResultModelsFactory;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyModel;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResultModel;
import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

import lombok.RequiredArgsConstructor;

/**
 * Key Management Service implementation: handles the key management of the service.
 * 
 * @author Marcel Eichelberger
 * 
 */
@RequiredArgsConstructor
@Service
public class KeyManagementService {
    // OWASP [106] Key Management Policy & Process

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyManagementService.class);
    private static final int KEY_SIZE = 256;

    private final KeyStoreHelper keyStoreHelper;
    private final ResultModelsFactory resultModelsFactory;
    private final ClientKeyRegistry clientKeyRegistry;

    /**
     * Generates a secure client key, 
     * 
     * @param generateKeyModel the model containing parameters for key generation
     * @return An object of GenerateKeyResultModel
     * SecureCodingPractices:
     * - OWASP [104] Secure Random Number Generation for Key and Alias
     * - OWASP [101] JWT generation and signing (done on server-side)
     */
    public final GenerateKeyResultModel generateKey(final GenerateKeyModel generateKeyModel) {
        final String clientName = generateKeyModel.getClientName();
        LOGGER.info("Starting key generation for client '{}'", clientName);

        final boolean clientNameExist = this.clientKeyRegistry.hasClient(clientName);
        if (clientNameExist) {
            final String message = String.format("Key already exists for client: '%s'", clientName);
            LOGGER.warn("Key generation skipped: {}", message);
            return this.resultModelsFactory.buildGenerateKeyResultModel(message);
        }

        final SecretKey aesKey = this.generateRandomKey();
        LOGGER.debug("Random AES key generated for client '{}'", clientName);

        final String keyAlias = this.generateRandomKeyAlias();
        LOGGER.debug("Random key alias generated for client '{}': {}", clientName, keyAlias);

        this.keyStoreHelper.storeKey(keyAlias, aesKey);
        LOGGER.info("Key stored in KeyStore for client '{}', alias '{}'", clientName, keyAlias);

        this.clientKeyRegistry.registerClientKey(clientName, keyAlias);
        LOGGER.info("Client '{}' registered with alias '{}'", clientName, keyAlias);

        final String message = String.format("Key generated for client: '%s'", clientName);
        return this.resultModelsFactory.buildGenerateKeyResultModel(message);
    }

    /**
     * Generates a random AES key and stores it in the KeyStore.
     *
     * @return A SecretKey object representing the generated AES key.
     * @throws InternalServerErrorException if there is an error during key generation.
     */
    private SecretKey generateRandomKey() {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException exception) {
            final ErrorCode errorCode = ErrorCode.AES_KEYGEN_SECURE_RANDOM_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While generating a random client key.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logError();
            throw new InternalServerErrorException(errorDetail);
        }
    
        final KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (final NoSuchAlgorithmException exception) {
            final ErrorCode errorCode = ErrorCode.AES_KEYGEN_INIT_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While preparing AES key generator for client key creation.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        keyGen.init(KEY_SIZE, secureRandom);
        return keyGen.generateKey();
    }

    /**
     * Generates a random key alias using a secure random number generator.
     *
     * @return A Base64 encoded string representing the random key alias.
     * @throws InternalServerErrorException if there is an error during secure random generation.
     */
    private String generateRandomKeyAlias() {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException exception) {
            final ErrorCode errorCode = ErrorCode.AES_KEYGEN_SECURE_RANDOM_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While generating a random client key alias.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }
        final byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes).toLowerCase();
    }
}
