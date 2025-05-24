package com.projectwork.cryptoservice.businesslogic;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

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
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;

    private final JwtManagementService jwtManagementService;
    private final KeyStoreHelper keyStoreHelper;
    private final ClientKeyRegistry clientKeyRegistry;
    private final ResultModelsFactory resultModelsFactory;

    public DecryptResultModel decrypt(final DecryptModel decryptModel, final String clientName) {
        final String issuedTo = jwtManagementService.extractIssuedTo(decryptModel.getJwt());
        if(!issuedTo.equals(clientName)) {
            throw new BadRequestException(
                ErrorCode.CLIENT_NAME_MISMATCH_ISSUED_TO.builder()
                    .withContext(String.format("JWT issuedTo='%s' does not match clientName='%s'", issuedTo, clientName))
                    .build()
            );
        }

        final String keyAlias = jwtManagementService.extractClientKeyAlias(decryptModel.getJwt());
        if(keyAlias == null) {
            throw new BadRequestException(
                ErrorCode.CLIENT_KEY_ALIAS_MISSING.builder()
                    .withContext("While extracting client key alias from JWT.")
                    .build()
            );
        }

        final SecretKey clientKey = keyStoreHelper.getClientKey(keyAlias);
        if(clientKey == null) {
            throw new BadRequestException(
                ErrorCode.NO_CLIENT_KEY_FOUND_FOR_ALIAS.builder()
                    .withContext(String.format("While retrieving client key for alias '%s'.", keyAlias))
                    .withLogMsgFormatted(keyAlias)
                    .build()
            );
        }

        final String clientNameFromKeyAlias = clientKeyRegistry.getClientNameByKeyAlias(keyAlias);
        if (clientNameFromKeyAlias == null) {
            throw new BadRequestException(
                ErrorCode.CLIENT_NAME_BY_ALIAS_NOT_FOUND.builder()
                    .withContext(String.format("While mapping key alias '%s' to client name.", keyAlias))
                    .withLogMsgFormatted(keyAlias)
                    .build()
            );
        }

        final byte[] iv = clientKeyRegistry.getIvForClient(clientNameFromKeyAlias);
        if (iv == null) {
            throw new BadRequestException(
                ErrorCode.IV_NOT_FOUND_FOR_CLIENT.builder()
                    .withContext(String.format("While retrieving IV for client with alias '%s'.", keyAlias))
                    .withLogMsgFormatted(clientNameFromKeyAlias)
                    .build()
            );
        }

        final String plainText = processDecryption(iv, clientKey, decryptModel.getCipherText());
        return resultModelsFactory.buildDecryptResultModel(plainText);
    }

    private String processDecryption(final byte[] iv, final SecretKey clientKey, final String cipherText) {
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
            throw new InternalServerErrorException(
                ErrorCode.AES_CIPHER_INSTANCE_FAILED.builder()
                    .withContext("While creating Cipher instance for decryption.")
                    .withException(exception)
                    .build()
            );
        }
    
        final GCMParameterSpec gcmParameterSpec;
        try {
            gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        } catch (final IllegalArgumentException exception) {
            throw new BadRequestException(
                ErrorCode.INVALID_GCM_PARAMETERS.builder()
                    .withContext("While constructing GCMParameterSpec for decryption.")
                    .withException(exception)
                    .build()
            );
        }
    
        try {
            cipher.init(Cipher.DECRYPT_MODE, clientKey, gcmParameterSpec);
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException | InvalidParameterException exception) {
            throw new InternalServerErrorException(
                ErrorCode.AES_CIPHER_INIT_FAILED.builder()
                    .withContext("While initializing Cipher for decryption with client key and GCM parameters.")
                    .withException(exception)
                    .build()
            );
        }
    
        final byte[] cipherTextBytes;
        try {
            cipherTextBytes = Base64.getDecoder().decode(cipherText);
        } catch (final IllegalArgumentException exception) {
            throw new BadRequestException(
                ErrorCode.INVALID_CIPHERTEXT_ENCODING.builder()
                    .withContext("While decoding cipher text from Base64 during decryption.")
                    .withException(exception)
                    .build()
            );
        }
    
        final byte[] decryptedBytes;
        try {
            decryptedBytes = cipher.doFinal(cipherTextBytes);
        } catch (final Exception exception) {
            throw new BadRequestException(
                ErrorCode.DECRYPTION_FAILED.builder()
                    .withContext("While decrypting cipher text using AES-GCM.")
                    .withException(exception)
                    .build()
            );
        }
    
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
    
}
