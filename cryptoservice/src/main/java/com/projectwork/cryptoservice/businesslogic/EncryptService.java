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
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;

    private final KeyStoreHelper keyStoreHelper;
    private final JwtManagementService jwtManagementService;
    private final ClientKeyRegistry clientKeyRegistry;
    private final ResultModelsFactory resultModelsFactory;

    public EncryptResultModel encrypt(final EncryptModel encryptModel, final String clientName) {
        final String keyAlias = jwtManagementService.extractClientKeyAlias(encryptModel.getJwt());
    
        if (!keyAlias.equals(clientKeyRegistry.getKeyAliasForClient(clientName))) {
            throw new BadRequestException(
                ErrorCode.CLIENT_KEY_ALIAS_MISMATCH_CLIENT_NAME.builder()
                    .withContext(String.format("JWT key alias '%s' does not match registered key alias for client '%s'.", keyAlias, clientName))
                    .build()
            );
        }
    
        final SecretKey clientKey = keyStoreHelper.getClientKey(keyAlias);
        if (clientKey == null) {
            throw new BadRequestException(
                ErrorCode.NO_CLIENT_KEY_FOUND_FOR_ALIAS.builder()
                    .withContext(String.format("While retrieving client key for alias '%s'.", keyAlias))
                    .withLogMsgFormatted(keyAlias)
                    .build()
            );
        }
    
        final byte[] iv = generateIV();
    
        clientKeyRegistry.updateIvForClient(clientName, iv);
        final String cipherText = processEncryption(iv, clientKey, encryptModel.getPlainText());
        return resultModelsFactory.buildEncryptResultModel(cipherText);
    }
    

    private byte[] generateIV() {
        SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException exception) {
            throw new InternalServerErrorException(
                ErrorCode.AES_KEYGEN_SECURE_RANDOM_FAILED.builder()
                    .withContext("While generating IV for encryption.")
                    .withException(exception)
                    .build()
            );
        }
        final byte[] iv = new byte[12]; // Standard IV size for GCM
        secureRandom.nextBytes(iv);
        return iv;
    }

    private String processEncryption(final byte[] iv, final SecretKey clientKey, final String plainText) {
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
            throw new InternalServerErrorException(
                ErrorCode.AES_CIPHER_INSTANCE_FAILED.builder()
                    .withContext("While creating Cipher instance for AES encryption.")
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
                    .withContext("While creating GCMParameterSpec for AES encryption.")
                    .withException(exception)
                    .build()
            );
        }
    
        try {
            cipher.init(Cipher.ENCRYPT_MODE, clientKey, gcmParameterSpec);
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException | InvalidParameterException exception) {
            throw new InternalServerErrorException(
                ErrorCode.AES_CIPHER_INIT_FAILED.builder()
                    .withContext("While initializing Cipher for AES encryption with client key and IV.")
                    .withException(exception)
                    .build()
            );
        }
    
        final byte[] encryptedData;
        try {
            encryptedData = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        } catch (final IllegalBlockSizeException | BadPaddingException exception) {
            throw new BadRequestException(
                ErrorCode.ENCRYPTION_FAILED.builder()
                    .withContext("While encrypting plainText using AES-GCM.")
                    .withException(exception)
                    .build()
            );
        }
    
        return Base64.getEncoder().encodeToString(encryptedData);
    }
    
}
