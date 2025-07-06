package com.projectwork.cryptoservice.businesslogic;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.*;
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
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptModel;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResultModel;
import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

import lombok.RequiredArgsConstructor;

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

    public final DecryptResultModel decrypt(final DecryptModel decryptModel, final String clientName) {
        LOGGER.info("Starting decryption for client '{}'.", clientName);

        final String jwt = decryptModel.getJwt();
        final String issuedTo = this.jwtManagementService.extractIssuedTo(jwt);
        if(!issuedTo.equals(clientName)) {
            final ErrorCode errorCode = ErrorCode.CLIENT_NAME_MISMATCH_ISSUED_TO;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format("JWT issuedTo='%s' does not match clientName='%s'", issuedTo, clientName);
            errorDetailBuilder.withContext(context);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            LOGGER.warn("Client name mismatch: {}", context);
            throw new BadRequestException(errorDetail);
        }

        final String keyAlias = this.jwtManagementService.extractClientKeyAlias(jwt);
        if(null == keyAlias) {
            final ErrorCode errorCode = ErrorCode.CLIENT_KEY_ALIAS_MISSING;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While extracting client key alias from JWT.");
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            LOGGER.warn("Client key alias is missing in JWT.");
            throw new BadRequestException(errorDetail);
        }

        final SecretKey clientKey = this.keyStoreHelper.getClientKey(keyAlias);
        if(null == clientKey) {
            final ErrorCode errorCode = ErrorCode.NO_CLIENT_KEY_FOUND_FOR_ALIAS;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format("While retrieving client key for alias '%s'.", keyAlias);
            errorDetailBuilder.withContext(context);
            errorDetailBuilder.withLogMsgFormatted(keyAlias);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            LOGGER.warn("No client key found for alias '{}'.", keyAlias);
            throw new BadRequestException(errorDetail);
        }

        final String clientNameFromKeyAlias = this.clientKeyRegistry.getClientNameByKeyAlias(keyAlias);
        if (null == clientNameFromKeyAlias) {
            final ErrorCode errorCode = ErrorCode.CLIENT_NAME_BY_ALIAS_NOT_FOUND;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format("While mapping key alias '%s' to client name.", keyAlias);
            errorDetailBuilder.withContext(context);
            errorDetailBuilder.withLogMsgFormatted(keyAlias);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            LOGGER.warn("Client name not found for key alias '{}'.", keyAlias);
            throw new BadRequestException(errorDetail);
        }

        final byte[] iv = this.clientKeyRegistry.getIvForClient(clientNameFromKeyAlias);
        if (null == iv) {
            final ErrorCode errorCode = ErrorCode.IV_NOT_FOUND_FOR_CLIENT;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format("While retrieving IV for client with alias '%s'.", keyAlias);
            errorDetailBuilder.withContext(context);
            errorDetailBuilder.withLogMsgFormatted(clientNameFromKeyAlias);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            LOGGER.warn("IV not found for client '{}'.", clientNameFromKeyAlias);
            throw new BadRequestException(errorDetail);
        }

        final String cipherText = decryptModel.getCipherText();
        final String plainText = this.processDecryption(iv, clientKey, cipherText);
        LOGGER.info("Decryption completed for client '{}'.", clientName);
        return this.resultModelsFactory.buildDecryptResultModel(plainText);
    }

    private String processDecryption(final byte[] iv, final SecretKey clientKey, final String cipherText) {
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            LOGGER.debug("Cipher instance created with algorithm '{}'.", ENCRYPTION_ALGORITHM);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
            final ErrorCode errorCode = ErrorCode.AES_CIPHER_INSTANCE_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While creating Cipher instance for decryption.");
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
            errorDetailBuilder.withContext("While constructing GCMParameterSpec for decryption.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }

        try {
            cipher.init(Cipher.DECRYPT_MODE, clientKey, gcmParameterSpec);
            LOGGER.debug("Cipher initialized for decryption mode.");
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException | InvalidParameterException exception) {
            final ErrorCode errorCode = ErrorCode.AES_CIPHER_INIT_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While initializing Cipher for decryption with client key and GCM parameters.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        }

        final byte[] cipherTextBytes;
        try {
            final Base64.Decoder decoder = Base64.getDecoder();
            cipherTextBytes = decoder.decode(cipherText);
            LOGGER.debug("Cipher text successfully decoded from Base64.");
        } catch (final IllegalArgumentException exception) {
            final ErrorCode errorCode = ErrorCode.INVALID_CIPHERTEXT_ENCODING;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While decoding cipher text from Base64 during decryption.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }

        final byte[] decryptedBytes;
        try {
            decryptedBytes = cipher.doFinal(cipherTextBytes);
            LOGGER.debug("Cipher text successfully decrypted.");
        } catch (final BadPaddingException | IllegalBlockSizeException exception) {
            final ErrorCode errorCode = ErrorCode.DECRYPTION_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While decrypting cipher text using AES-GCM.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
