package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyModel;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;
import com.projectwork.cryptoservice.factory.ResultModelsFactory;

/**
 * Key Management Service implementation: handles the key management of the service.
 * 
 * @author Marcel Eichelberger
 * 
 */
@Service
public class KeyManagementService {

    // OWASP [106] Key Management Policy & Process
    private final KeyStoreHelper keyStoreHelper;
    private final ResultModelsFactory resultModelsFactory;
    private final ClientKeyDataMap clientKeyAliasMap;

    public KeyManagementService(final KeyStoreHelper keyStoreHelper, final ResultModelsFactory resultModelsFactory, final ClientKeyDataMap clientKeyAliasMap) {
        this.clientKeyAliasMap = clientKeyAliasMap;
        this.keyStoreHelper = keyStoreHelper;
        this.resultModelsFactory = resultModelsFactory;
    }

    /**
     * Generates a secure client key, 
     * 
     * @return An object of GenerateKeyResultModel
     * @throws Exception
     * 
     * SecureCodingPractices:
     * - OWASP [104] Secure Random Number Generation for Key and Alias
     * - OWASP [101] JWT generation and signing (done on server-side)
     */
    public GenerateKeyResultModel generateKey(final GenerateKeyModel generateKeyModel) {
        final boolean clientNameExist = clientKeyAliasMap.containsClient(generateKeyModel.getClientName());
        if (clientNameExist) {
            System.out.println("Key already exists for client: " + generateKeyModel.getClientName());
            return resultModelsFactory.buildGenerateKeyResultModel("Key already exists for client: " + generateKeyModel.getClientName());
        }

        try {
            final SecretKey aesKey = generateRandomKey();
            final String keyAlias = generateRandomKeyAlias(); // OWASP [104] SecureRandom for unguessable alias
            keyStoreHelper.storeKey(keyAlias, aesKey);
            clientKeyAliasMap.addClientKeyAlias(generateKeyModel.getClientName(), keyAlias);
        } catch (Exception exception) {
            // TODO Auto-generated catch block
            exception.printStackTrace();
        }
        
        return resultModelsFactory.buildGenerateKeyResultModel("Key generated for client: " + generateKeyModel.getClientName());
    }

    private SecretKey generateRandomKey() throws Exception {
        final SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, secureRandom); // OWASP [104] SecureRandom for cryptographic key generation
        return keyGen.generateKey();
    }

    private String generateRandomKeyAlias() throws Exception {
        final SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        final byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes).toLowerCase(); // OWASP [104] SecureRandom for unguessable alias
    }
}
