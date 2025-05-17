package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.entity.factory.ResultModelsFactory;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyModel;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResultModel;

import lombok.RequiredArgsConstructor;

/**
 * Key Management Service implementation: handles the key management of the service.
 * 
 * @author Marcel Eichelberger
 * 
 */
@RequiredArgsConstructor
@Service
public class KeyManagementService {
    // OWASP [106] Key Management Policy & Process
    private final KeyStoreHelper keyStoreHelper;
    private final ResultModelsFactory resultModelsFactory;
    private final ClientKeyRegistry clientKeyRegistry;

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
        final boolean clientNameExist = clientKeyRegistry.hasClient(generateKeyModel.getClientName());
        if (clientNameExist) {
            System.out.println("Key already exists for client: " + generateKeyModel.getClientName());
            return resultModelsFactory.buildGenerateKeyResultModel("Key already exists for client: " + generateKeyModel.getClientName());
        }

        try {
            final SecretKey aesKey = generateRandomKey();
            final String keyAlias = generateRandomKeyAlias(); // OWASP [104] SecureRandom for unguessable alias
            keyStoreHelper.storeKey(keyAlias, aesKey);
            clientKeyRegistry.registerClientKey(generateKeyModel.getClientName(), keyAlias);
        } catch (final NoSuchAlgorithmException exception) {
            // TODO Auto-generated catch block
            throw new RuntimeException("Error generating key: " + exception.getMessage());
        }
        
        return resultModelsFactory.buildGenerateKeyResultModel("Key generated for client: " + generateKeyModel.getClientName());
    }

    private SecretKey generateRandomKey() throws NoSuchAlgorithmException {
        final SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, secureRandom); // OWASP [104] SecureRandom for cryptographic key generation
        return keyGen.generateKey();
    }

    private String generateRandomKeyAlias() throws NoSuchAlgorithmException {
        final SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        final byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes).toLowerCase(); // OWASP [104] SecureRandom for unguessable alias
    }
}
