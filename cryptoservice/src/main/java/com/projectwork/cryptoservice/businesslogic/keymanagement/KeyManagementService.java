package com.projectwork.cryptoservice.businesslogic.keymanagement;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.JwtService;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;
import com.projectwork.cryptoservice.factory.ResultModelsFactory;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Key Management Service implementation: handles the key management of the service.
 * 
 * @author Marcel Eichelberger
 * 
 * TODO: MAster key rotation
 */
@Service
public class KeyManagementService {

    // OWASP [106] Key Management Policy & Process
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
     * - OWASP [104] Secure Random Number Generation for Key and Alias
     * - OWASP [101] JWT generation and signing (done on server-side)
     */
    public GenerateKeyResultModel generateKey() throws Exception {
        final SecureRandom secureRandom = SecureRandom.getInstanceStrong(); 
        
        final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, secureRandom); // OWASP [104] SecureRandom for cryptographic key generation
        final SecretKey aesKey = keyGen.generateKey();

        final byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        final String keyAlias = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes); // OWASP [104] SecureRandom for unguessable alias

        keyStoreHelper.storeKey(keyAlias, aesKey);
        final String jwtString = jwtService.generateJwt(keyAlias); // OWASP [101] JWT generation and signing (done on server-side)
        return resultModelsFactory.buildGenerateKeyResultModel(jwtString);
    }

    /**
     * 
     * @param jwtToken
     * @return
     * @throws Exception
     * 
     * SecureCodingPractices
     * - OWASP [101] All cryptographic operations on the server
     */
    public SecretKey getKeyFromJwt(String jwtToken) throws Exception {
        String keyAlias = jwtService.getKeyAliasFromJwt(jwtToken);
        return keyStoreHelper.getKey(keyAlias); // OWASP [101] All cryptographic operations on the server
    }
}
