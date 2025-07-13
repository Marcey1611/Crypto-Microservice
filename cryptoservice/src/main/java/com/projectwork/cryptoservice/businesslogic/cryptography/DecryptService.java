package com.projectwork.cryptoservice.businesslogic.cryptography;

import com.projectwork.cryptoservice.businesslogic.jwtmanagement.JwtManagementService;
import com.projectwork.cryptoservice.businesslogic.keymanagement.ClientKeyRegistry;
import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.factory.ResultModelsFactory;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptModel;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResultModel;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Service for decrypting texts using AES-GCM.
 * Handles key management, IV retrieval, and error handling for decryption operations.
 */
@RequiredArgsConstructor
@Service
public class DecryptService {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptService.class);

    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;

    private final JwtManagementService jwtManagementService;
    private final KeyStoreHelper keyStoreHelper;
    private final ClientKeyRegistry clientKeyRegistry;
    private final ResultModelsFactory resultModelsFactory;
    private final ErrorHandler errorHandler;
    private final CryptoUtility cryptoUtility;

    /**
     * Decrypts a cipher text for a given client.
     * @param decryptModel The model containing cipher text and JWT.
     * @param clientName The name of the client.
     * @return The result of the decryption.
     */
    public final DecryptResultModel decrypt(final DecryptModel decryptModel, final String clientName) {
        LOGGER.info("Starting decryption for client '{}'.", clientName);

        this.validateClientName(decryptModel, clientName);
        final String keyAlias = this.extractKeyAlias(decryptModel);
        final SecretKey clientKey = this.retrieveClientKey(keyAlias);
        final String clientNameFromKeyAlias = this.mapKeyAliasToClientName(keyAlias);
        final byte[] iv = this.retrieveIvForClient(clientNameFromKeyAlias);
        final String cipherText = decryptModel.getCipherText();
        final String plainText = this.processDecryption(iv, clientKey, cipherText);
        LOGGER.info("Decryption completed for client '{}'.", clientName);
        return this.resultModelsFactory.buildDecryptResultModel(plainText);
    }

    /**
     * Validates that the client name matches the issuedTo field in the JWT.
     * @param decryptModel The decryption model containing the JWT.
     * @param clientName The name of the client.
     */
    private void validateClientName(final DecryptModel decryptModel, final String clientName) {
        final String jwt = decryptModel.getJwt();
        final String issuedTo = this.jwtManagementService.extractIssuedTo(jwt);
        if (!issuedTo.equals(clientName)) {
            final String context = String.format("JWT issuedTo='%s' does not match clientName='%s'", issuedTo, clientName);
            throw this.errorHandler.handleError(
                ErrorCode.CLIENT_NAME_MISMATCH_ISSUED_TO,
                context
            );
        }
    }

    /**
     * Extracts the key alias from the JWT in the decryption model.
     * @param decryptModel The decryption model containing the JWT.
     * @return The extracted key alias.
     */
    private String extractKeyAlias(final DecryptModel decryptModel) {
        final String jwt = decryptModel.getJwt();
        final String keyAlias = this.jwtManagementService.extractClientKeyAlias(jwt);
        if (null == keyAlias) {
            throw this.errorHandler.handleError(
                ErrorCode.CLIENT_KEY_ALIAS_MISSING,
                "Client key alias is missing in the JWT"
            );
        }
        return keyAlias;
    }

    /**
     * Retrieves the client key for the given key alias.
     * @param keyAlias The key alias.
     * @return The SecretKey for the client.
     */
    private SecretKey retrieveClientKey(final String keyAlias) {
        final SecretKey clientKey = this.keyStoreHelper.getClientKey(keyAlias);
        if (null == clientKey) {
            final String context = String.format("While retrieving client key for alias '%s'.", keyAlias);
            throw this.errorHandler.handleError(
                keyAlias,
                ErrorCode.NO_CLIENT_KEY_FOUND_FOR_ALIAS,
                context
            );
        }
        return clientKey;
    }

    /**
     * Maps a key alias to the corresponding client name.
     * @param keyAlias The key alias.
     * @return The client name associated with the key alias.
     */
    private String mapKeyAliasToClientName(final String keyAlias) {
        final String clientNameFromKeyAlias = this.clientKeyRegistry.getClientNameByKeyAlias(keyAlias);
        if (null == clientNameFromKeyAlias) {
            final String context = String.format("While mapping key alias '%s' to client name.", keyAlias);
            throw this.errorHandler.handleError(
                keyAlias,
                ErrorCode.CLIENT_NAME_BY_ALIAS_NOT_FOUND,
                context
            );
        }
        return clientNameFromKeyAlias;
    }

    /**
     * Retrieves the IV for the client by name.
     * @param clientNameFromKeyAlias The client name associated with the key alias.
     * @return The IV for the client.
     */
    private byte[] retrieveIvForClient(final String clientNameFromKeyAlias) {
        final byte[] iv = this.clientKeyRegistry.getIvForClient(clientNameFromKeyAlias);
        if (null == iv) {
            final String context = String.format("While retrieving IV for client with alias '%s'.", clientNameFromKeyAlias);
            throw this.errorHandler.handleError(
                clientNameFromKeyAlias,
                ErrorCode.IV_NOT_FOUND_FOR_CLIENT,
                context
            );
        }
        return iv;
    }

    /**
     * Processes the decryption of the cipher text using the provided IV and key.
     * @param iv The initialization vector.
     * @param clientKey The secret key for decryption.
     * @param cipherText The cipher text to decrypt.
     * @return The decrypted plain text.
     */
    private String processDecryption(final byte[] iv, final SecretKey clientKey, final String cipherText) {
        final Cipher cipher = this.cryptoUtility.createCipher();
        final GCMParameterSpec gcmParameterSpec = this.cryptoUtility.createGCMParameterSpec(iv);
        this.cryptoUtility.initCipher(cipher, clientKey, gcmParameterSpec, Cipher.DECRYPT_MODE);
        final byte[] cipherTextBytes = this.decodeCipherText(cipherText);
        return this.decryptCipherText(cipher, cipherTextBytes);
    }

    /**
     * Decodes the cipher text from Base64 encoding.
     * @param cipherText The Base64 encoded cipher text.
     * @return The decoded cipher text bytes.
     */
    private byte[] decodeCipherText(final String cipherText) {
        try {
            final Base64.Decoder decoder = Base64.getDecoder();
            final byte[] cipherTextBytes = decoder.decode(cipherText);
            LOGGER.debug("Cipher text successfully decoded from Base64.");
            return cipherTextBytes;
        } catch (final IllegalArgumentException exception) {
            throw this.errorHandler.handleError(
                ErrorCode.INVALID_CIPHERTEXT_ENCODING,
                "While decoding cipher text from Base64 during decryption.",
                exception
            );
        }
    }

    /**
     * Decrypts the cipher text bytes using the Cipher instance.
     * @param cipher The Cipher instance.
     * @param cipherTextBytes The cipher text bytes.
     * @return The decrypted plain text.
     */
    private String decryptCipherText(final Cipher cipher, final byte[] cipherTextBytes) {
        try {
            final byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);
            LOGGER.debug("Cipher text successfully decrypted.");
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (final BadPaddingException | IllegalBlockSizeException exception) {
            throw this.errorHandler.handleError(
                ErrorCode.DECRYPTION_FAILED,
                "While decrypting cipher text using AES-GCM.",
                exception
            );
        }
    }
}
