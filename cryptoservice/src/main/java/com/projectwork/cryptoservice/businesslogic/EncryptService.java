package com.projectwork.cryptoservice.businesslogic;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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
import com.projectwork.cryptoservice.businesslogic.keymanagement.ClientKeyDataMap;
import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.encrypt.EncryptModel;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResultModel;
import com.projectwork.cryptoservice.factory.ResultModelsFactory;

@Service
public class EncryptService {
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;

    private final KeyStoreHelper keyStoreHelper;
    private final JwtManagementService jwtManagementService;
    private final ClientKeyDataMap clientKeyAliasMap;
    private final ResultModelsFactory resultModelsFactory;

    public EncryptService(final KeyStoreHelper keyStoreHelper, final JwtManagementService jwtManagementService, final ClientKeyDataMap clientKeyAliasMap, final ResultModelsFactory resultModelsFactory) {
        this.resultModelsFactory = resultModelsFactory;
        this.clientKeyAliasMap = clientKeyAliasMap;
        this.keyStoreHelper = keyStoreHelper;
        this.jwtManagementService = jwtManagementService;
    }

    public EncryptResultModel encrypt(final EncryptModel encryptModel, final String clientName) {
        final String keyAlias = jwtManagementService.extractClientKeyAlias(encryptModel.getJwt());
        if(keyAlias == clientKeyAliasMap.getKeyAlias(clientName)){
            throw new RuntimeException("Client key alias does not match the client name");
        }
        final SecretKey clientKey = keyStoreHelper.getClientKey(keyAlias);
        final byte[] iv = generateIV();
        clientKeyAliasMap.putIv(iv, clientName);
        final String cipherText = processEncryption(iv, clientKey, encryptModel.getPlainText());
        return resultModelsFactory.buildEncryptResultModel(cipherText);
    }

    private byte[] generateIV() {
        final SecureRandom secureRandom = new SecureRandom();
        final byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        return iv;
    }

    private String processEncryption(final byte[] iv, final SecretKey clientKey, final String plainText) {
        byte[] encryptedData = null;
        try {
            final Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, clientKey, gcmParameterSpec);
            encryptedData = cipher.doFinal(plainText.getBytes());
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException exception) {
            // TODO Auto-generated catch block
            exception.printStackTrace();
        }
        //TODO: return byte[] not String
        return Base64.getEncoder().encodeToString(encryptedData);
    }
}
