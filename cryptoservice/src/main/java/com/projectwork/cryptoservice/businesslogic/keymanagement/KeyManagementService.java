package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.entity.factory.ResultModelsFactory;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyModel;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResultModel;
import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Key Management Service implementation: handles the key management of the service.
 * 
 * @author Marcel Eichelberger
 * 
 */
@RequiredArgsConstructor
@Service
public class KeyManagementService {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyManagementService.class);
    private static final int KEY_SIZE = 256;

    private final KeyStoreHelper keyStoreHelper;
    private final ResultModelsFactory resultModelsFactory;
    private final ClientKeyRegistry clientKeyRegistry;
    private final ErrorHandler errorHandler;

    /**
     * Generates a secure client key, 
     * 
     * @param generateKeyModel the model containing parameters for key generation
     * @return An object of GenerateKeyResultModel
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
            throw this.errorHandler.handleError(
                    ErrorCode.AES_KEYGEN_SECURE_RANDOM_FAILED,
            "While generating a random client key.",
                    exception
            );
        }
    
        final KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (final NoSuchAlgorithmException exception) {
            throw this.errorHandler.handleError(
                    ErrorCode.AES_KEYGEN_INIT_FAILED,
                    "While preparing AES key generator for client key creation.",
                    exception
            );
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
            throw this.errorHandler.handleError(
                    ErrorCode.AES_KEYGEN_SECURE_RANDOM_FAILED,
                    "While generating a random client key alias.",
                    exception
            );
        }
        final byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes).toLowerCase();
    }
}
