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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Service for decrypting texts using AES-GCM.
 *
 * SCPs:
 *  - [101] All cryptographic functions used to protect secrets from the application user must be implemented on a trusted system (e.g., the server)
 *  - [114] Logging controls should support both success and failure of specified security events
 *  - [129] Log cryptographic module failures
 */
@RequiredArgsConstructor
@Service
public class DecryptService {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptService.class);

    private final JwtManagementService jwtManagementService;
    private final KeyStoreHelper keyStoreHelper;
    private final ClientKeyRegistry clientKeyRegistry;
    private final ResultModelsFactory resultModelsFactory;
    private final ErrorHandler errorHandler;
    private final CryptoUtility cryptoUtility;

    @Value("${client.keystore.path}")
    private String clientKeystorePath;

    @Value("${client.keystore.password}")
    private String clientKeystorePassword;

    /**
     * Decrypts a cipher text for a given client.
     * @param decryptModel The model containing cipher text and JWT.
     * @param clientName The name of the client.
     * @return The result of the decryption.
     */
    public final DecryptResultModel decrypt(final DecryptModel decryptModel, final String clientName) {
        LOGGER.info("Starting decryption for client '{}'.", clientName);

        final String keyAlias = this.jwtManagementService.extractClientKeyAlias(decryptModel.getJwt());
        final SecretKey clientKey = this.retrieveClientKey(keyAlias);
        final String clientNameFromKeyAlias = this.mapKeyAliasToClientName(keyAlias);
        final byte[] iv = this.retrieveIvForClient(clientNameFromKeyAlias);
        final String cipherText = decryptModel.getCipherText();
        final String plainText = this.processDecryption(iv, clientKey, cipherText, clientName);
        LOGGER.info("Decryption completed for client '{}'.", clientName);
        return this.resultModelsFactory.buildDecryptResultModel(plainText);
    }

    /**
     * Retrieves the client key for the given key alias.
     * @param keyAlias The key alias.
     * @return The SecretKey for the client.
     */
    private SecretKey retrieveClientKey(final String keyAlias) {
        final SecretKey clientKey = this.keyStoreHelper.getClientKey(keyAlias, this.clientKeystorePath, this.clientKeystorePassword);
        if (null == clientKey) {
            throw this.errorHandler.handleClientError(
                keyAlias,
                ErrorCode.NO_CLIENT_KEY_FOUND_FOR_ALIAS,
                "While retrieving client key."
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
        return this.clientKeyRegistry.getClientNameByKeyAlias(keyAlias);
    }

    /**
     * Retrieves the IV for the client by name.
     * @param clientNameFromKeyAlias The client name associated with the key alias.
     * @return The IV for the client.
     */
    private byte[] retrieveIvForClient(final String clientNameFromKeyAlias) {
        final byte[] iv = this.clientKeyRegistry.getIvForClient(clientNameFromKeyAlias);
        if (null == iv) {
            throw this.errorHandler.handleClientError(
                clientNameFromKeyAlias,
                ErrorCode.IV_NOT_FOUND_FOR_CLIENT,
                "While retrieving IV for client."
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
    private String processDecryption(final byte[] iv, final SecretKey clientKey, final String cipherText, final String clientName) {
        final Cipher cipher = this.cryptoUtility.createCipher();
        final GCMParameterSpec gcmParameterSpec = this.cryptoUtility.createGCMParameterSpec(iv);
        this.cryptoUtility.initCipher(cipher, clientKey, gcmParameterSpec, Cipher.DECRYPT_MODE);
        cipher.updateAAD(clientName.getBytes(StandardCharsets.UTF_8));
        final byte[] cipherTextBytes = this.decodeCipherText(cipherText);
        return this.decryptCipherText(cipher, cipherTextBytes);
    }

    /**
     * Decodes the cipher text from Base64 encoding.
     * @param cipherText The Base64 encoded cipher text.
     * @return The decoded cipher text bytes.
     *
     * SCP103
     */
    private byte[] decodeCipherText(final String cipherText) {
        try {
            final Base64.Decoder decoder = Base64.getDecoder();
            final byte[] cipherTextBytes = decoder.decode(cipherText);
            LOGGER.debug("Cipher text successfully decoded from Base64.");
            return cipherTextBytes;
        } catch (final IllegalArgumentException exception) {
            throw this.errorHandler.handleBusinessError(
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
     *
     * SCP103
     */
    private String decryptCipherText(final Cipher cipher, final byte[] cipherTextBytes) {
        try {
            final byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);
            LOGGER.debug("Cipher text successfully decrypted.");
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (final BadPaddingException | IllegalBlockSizeException exception) {
            throw this.errorHandler.handleBusinessError(
                ErrorCode.DECRYPTION_FAILED,
                "While decrypting cipher text using AES-GCM.",
                exception
            );
        }
    }
}
