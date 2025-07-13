package com.projectwork.cryptoservice.businesslogic.cryptography;

import com.projectwork.cryptoservice.businesslogic.jwtmanagement.JwtManagementService;
import com.projectwork.cryptoservice.businesslogic.keymanagement.ClientKeyRegistry;
import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.factory.ResultModelsFactory;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptModel;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResultModel;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * Service for encrypting texts using AES-GCM.
 * Handles key management, IV generation, and error handling for encryption operations.
 */
@RequiredArgsConstructor
@Service
public class EncryptService {
    private static final Logger LOGGER = LoggerFactory.getLogger(EncryptService.class);

    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;

    private final KeyStoreHelper keyStoreHelper;
    private final JwtManagementService jwtManagementService;
    private final ClientKeyRegistry clientKeyRegistry;
    private final ResultModelsFactory resultModelsFactory;
    private final ErrorHandler errorHandler;
    private final CryptoUtility cryptoUtility;

    /**
     * Encrypts a plain text for a given client.
     * @param encryptModel The model containing plain text and JWT.
     * @param clientName The name of the client.
     * @return The result of the encryption.
     */
    public final EncryptResultModel encrypt(final EncryptModel encryptModel, final String clientName) {
        LOGGER.info("Starting encryption process for client '{}'.", clientName);

        final String jwt = encryptModel.getJwt();
        final String keyAlias = this.jwtManagementService.extractClientKeyAlias(jwt);
        this.validateKeyAlias(keyAlias, clientName);
        final SecretKey clientKey = this.getClientKey(keyAlias);
        final byte[] iv = this.generateIV();
        this.clientKeyRegistry.updateIvForClient(clientName, iv);
        final String plainText = encryptModel.getPlainText();
        final String cipherText = this.encryptPlainText(iv, clientKey, plainText);
        LOGGER.info("Encryption completed for client '{}'.", clientName);
        return this.resultModelsFactory.buildEncryptResultModel(cipherText);
    }

    /**
     * Validates that the key alias matches the registered alias for the client.
     * @param keyAlias The key alias from the JWT.
     * @param clientName The name of the client.
     */
    private void validateKeyAlias(final String keyAlias, final String clientName) {
        final String keyAliasForClient = this.clientKeyRegistry.getKeyAliasForClient(clientName);
        if (!keyAlias.equals(keyAliasForClient)) {
            final String context = String.format(
                    "JWT key alias '%s' does not match registered key alias for client '%s'.",
                    keyAlias,
                    clientName
            );
            throw this.errorHandler.handleError(
                    ErrorCode.CLIENT_KEY_ALIAS_MISMATCH_CLIENT_NAME,
                    context
            );
        }
    }

    /**
     * Retrieves the client key for the given key alias or throws an error if not found.
     * @param keyAlias The key alias.
     * @return The SecretKey for the client.
     */
    private SecretKey getClientKey(final String keyAlias) {
        final SecretKey clientKey = this.keyStoreHelper.getClientKey(keyAlias);
        if (null == clientKey) {
            final String context = String.format(
                    "While retrieving client key for alias '%s'.",
                    keyAlias
            );
            throw this.errorHandler.handleError(
                    ErrorCode.NO_CLIENT_KEY_FOUND_FOR_ALIAS,
                    context
            );
        }
        return clientKey;
    }

    /**
     * Encrypts the plain text using the provided IV and key.
     * @param iv The initialization vector.
     * @param clientKey The secret key for encryption.
     * @param plainText The plain text to encrypt.
     * @return The encrypted text (Base64 encoded).
     */
    private String encryptPlainText(final byte[] iv, final SecretKey clientKey, final String plainText) {
        final Cipher cipher = this.cryptoUtility.createCipher();
        final GCMParameterSpec gcmParameterSpec = this.cryptoUtility.createGCMParameterSpec(iv);
        this.cryptoUtility.initCipher(cipher, clientKey, gcmParameterSpec, Cipher.ENCRYPT_MODE);
        final byte[] encryptedData = this.encryptData(cipher, plainText);
        return this.encodeBase64(encryptedData);
    }

    /**
     * Encrypts the plain text using the Cipher instance.
     * @param cipher The Cipher instance.
     * @param plainText The plain text to encrypt.
     * @return The encrypted data bytes.
     */
    private byte[] encryptData(final Cipher cipher, final String plainText) {
        try {
            final byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
            final byte[] encryptedData = cipher.doFinal(plainTextBytes);
            LOGGER.debug("Plaintext successfully encrypted.");
            return encryptedData;
        } catch (final IllegalBlockSizeException | BadPaddingException exception) {
            throw this.errorHandler.handleError(
                ErrorCode.ENCRYPTION_FAILED,
                exception,
                "While encrypting plaintext using AES-GCM."
            );
        }
    }

    /**
     * Encodes the encrypted data as a Base64 string.
     * @param encryptedData The encrypted data bytes.
     * @return The Base64 encoded string.
     */
    private String encodeBase64(final byte[] encryptedData) {
        final Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(encryptedData);
    }

    /**
     * Generates an initialization vector (IV) for AES-GCM.
     * @return The generated IV.
     */
    private byte[] generateIV() {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
            LOGGER.debug("SecureRandom instance for IV generation successfully created.");
        } catch (final NoSuchAlgorithmException exception) {
            throw this.errorHandler.handleError(
                ErrorCode.AES_KEYGEN_SECURE_RANDOM_FAILED,
                "While generating IV for encryption.",
                exception
            );
        }
        final byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        return iv;
    }
}