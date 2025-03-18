package com.projectwork.cryptoservice.businesslogic;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;
import com.projectwork.cryptoservice.factory.ResultModelsFactory;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

/**
 * Key Management Service implementation: handles the key management of the service.
 * 
 * @author Marcel Eichelberger
 * 
 * TODO: MAster key rotation
 */
@Service
public class KeyManagementService {

    private final KeyStoreHelper keyStoreHelper;
    private final JwtService jwtService;
    private final ResultModelsFactory resultModelsFactory;

    public KeyManagementService(KeyStoreHelper keyStoreHelper, JwtService jwtService, ResultModelsFactory resultModelsFactory) {
        this.keyStoreHelper = keyStoreHelper;
        this.jwtService = jwtService;
        this.resultModelsFactory = resultModelsFactory;
    }

    /**
     * Generates a secure client key, 
     * 
     * @return An object of GenerateKeyResultModel
     * @throws Exception
     * 
     * SecureCodingPractices:
     * - OWASP 104 Secure Random Number Generation: Key generation uses SecureRandom.getInstanceStrong() as cryptographical secure random source 
     */
    public GenerateKeyResultModel generateKey() throws Exception {
        final SecureRandom secureRandom = SecureRandom.getInstanceStrong(); 
        
        final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, secureRandom); // OWASP 104 Secure Random Number Generation
        final SecretKey aesKey = keyGen.generateKey();

        final byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        final String keyAlias = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes); // OWASP 104 Secure Random Number Generation

        keyStoreHelper.storeKey(keyAlias, aesKey);
        final String jwtString = jwtService.generateJwt(keyAlias);
        return resultModelsFactory.buildGenerateKeyResultModel(jwtString);
    }

    public SecretKey getKeyFromJwt(String jwtToken) throws Exception {
        String keyAlias = jwtService.getKeyAliasFromJwt(jwtToken);
        return keyStoreHelper.getKey(keyAlias);
    }
}
