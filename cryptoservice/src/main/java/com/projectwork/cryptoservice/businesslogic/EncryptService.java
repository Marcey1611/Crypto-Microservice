package com.projectwork.cryptoservice.businesslogic;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.jwtmanagement.JwtManagementService;
import com.projectwork.cryptoservice.businesslogic.keymanagement.ClientKeyRegistry;
import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.factory.ResultModelsFactory;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptModel;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResultModel;
import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

import lombok.RequiredArgsConstructor;

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

    public final EncryptResultModel encrypt(final EncryptModel encryptModel, final String clientName) {
        LOGGER.info("Starting encryption process for client '{}'.", clientName);

        final String jwt = encryptModel.getJwt();
        final String keyAlias = this.jwtManagementService.extractClientKeyAlias(jwt);

        final String keyAliasForClient = this.clientKeyRegistry.getKeyAliasForClient(clientName);
        if (!keyAlias.equals(keyAliasForClient)) {
            final ErrorCode errorCode = ErrorCode.CLIENT_KEY_ALIAS_MISMATCH_CLIENT_NAME;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format(
                    "JWT key alias '%s' does not match registered key alias for client '%s'.",
                    keyAlias,
                    clientName
            );
            errorDetailBuilder.withContext(context);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            LOGGER.warn("Key alias mismatch: {}", context);
            throw new BadRequestException(errorDetail);
        }

        final SecretKey clientKey = this.keyStoreHelper.getClientKey(keyAlias);
        if (null == clientKey) {
            final ErrorCode errorCode = ErrorCode.NO_CLIENT_KEY_FOUND_FOR_ALIAS;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format(
                    "While retrieving client key for alias '%s'.",
                    keyAlias
            );
            errorDetailBuilder.withContext(context);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            LOGGER.warn("No client key found for alias '{}'.", keyAlias);
            throw new BadRequestException(errorDetail);
        }

        final byte[] iv = this.generateIV();
        LOGGER.debug("Generated IV for client '{}': {}", clientName, Base64.getEncoder().encodeToString(iv));
        this.clientKeyRegistry.updateIvForClient(clientName, iv);

        final String plainText = encryptModel.getPlainText();
        final String cipherText = this.processEncryption(iv, clientKey, plainText);
        LOGGER.info("Encryption completed for client '{}'.", clientName);
        return this.resultModelsFactory.buildEncryptResultModel(cipherText);
    }

    private byte[] generateIV() {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
            LOGGER.debug("SecureRandom instance for IV generation successfully created.");
        } catch (final NoSuchAlgorithmException exception) {
            final ErrorCode errorCode = ErrorCode.AES_KEYGEN_SECURE_RANDOM_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While generating IV for encryption.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }
        final byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        return iv;
    }

    private String processEncryption(final byte[] iv, final SecretKey clientKey, final String plainText) {
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            LOGGER.debug("Cipher instance created with algorithm '{}'.", ENCRYPTION_ALGORITHM);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
            final ErrorCode errorCode = ErrorCode.AES_CIPHER_INSTANCE_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While creating Cipher instance for AES encryption.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }

        final GCMParameterSpec gcmParameterSpec;
        try {
            gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            LOGGER.debug("GCMParameterSpec created with tag length {}.", GCM_TAG_LENGTH);
        } catch (final IllegalArgumentException exception) {
            final ErrorCode errorCode = ErrorCode.INVALID_GCM_PARAMETERS;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While creating GCMParameterSpec for AES encryption.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }

        try {
            cipher.init(Cipher.ENCRYPT_MODE, clientKey, gcmParameterSpec);
            LOGGER.debug("Cipher initialized for encryption mode.");
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException | InvalidParameterException exception) {
            final ErrorCode errorCode = ErrorCode.AES_CIPHER_INIT_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While initializing Cipher for AES encryption with client key and IV.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }

        final byte[] encryptedData;
        try {
            final byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
            encryptedData = cipher.doFinal(plainTextBytes);
            LOGGER.debug("Plaintext successfully encrypted.");
        } catch (final IllegalBlockSizeException | BadPaddingException exception) {
            final ErrorCode errorCode = ErrorCode.ENCRYPTION_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While encrypting plainText using AES-GCM.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }

        final Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(encryptedData);
    }
}