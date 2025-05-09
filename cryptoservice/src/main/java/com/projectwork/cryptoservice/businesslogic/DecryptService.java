package com.projectwork.cryptoservice.businesslogic;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.jwtmanagement.JwtManagementService;
import com.projectwork.cryptoservice.businesslogic.keymanagement.ClientKeyDataMap;
import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.factory.ResultModelsFactory;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptModel;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResultModel;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class DecryptService {
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;

    private final JwtManagementService jwtManagementService;
    private final KeyStoreHelper keyStoreHelper;
    private final ClientKeyDataMap clientKeyAliasMap;
    private final ResultModelsFactory resultModelsFactory;

    public DecryptResultModel decrypt(final DecryptModel decryptModel, final String clientName) {
        final String issuedTo = jwtManagementService.extractIssuedTo(decryptModel.getJwt());
        if(!issuedTo.equals(clientName)) {
            throw new RuntimeException("Client name does not match the issuedTo in the JWT");
        }

        final String keyAlias = jwtManagementService.extractClientKeyAlias(decryptModel.getJwt());
        if(keyAlias == null) {
            throw new RuntimeException("Key alias not found in the JWT");
        }

        final SecretKey clientKey = keyStoreHelper.getClientKey(keyAlias);
        if(clientKey == null) {
            throw new RuntimeException("Client key not found for key alias: " + keyAlias);
        }

        final String clientNameFromKeyAlias = clientKeyAliasMap.getClientName(keyAlias);
        if(clientNameFromKeyAlias == null) {
            throw new RuntimeException("Client name not found for key alias: " + keyAlias);
        }

        final byte[] iv = clientKeyAliasMap.getIv(clientNameFromKeyAlias);
        if(iv == null) {
            throw new RuntimeException("IV not found for key alias: " + keyAlias);
        }

        final String plainText = processDecryption(iv, clientKey, decryptModel.getCipherText());
        if(plainText == null) {
            throw new RuntimeException("Decryption failed");
        }
        return resultModelsFactory.buildDecryptResultModel(plainText);
    }

    private String processDecryption(final byte[] iv, final SecretKey clientKey, final String cipherText) {
        try {
            final Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, clientKey, gcmParameterSpec);
            final byte[] cipherTextBytes = Base64.getDecoder().decode(cipherText);
            final byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);
            //TODO: return byte[] not String
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (final Exception exception) {
            throw new RuntimeException("Decryption failed", exception);
        }
    }
}
