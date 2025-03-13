package com.projectwork.cryptoservice.businesslogic;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;
import com.projectwork.cryptoservice.factory.ResultModelsFactory;

import java.util.UUID;

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

    public GenerateKeyResultModel generateKey() throws Exception {
        System.out.println("Generating key");
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        String keyAlias = UUID.randomUUID().toString();

        keyStoreHelper.storeKey(keyAlias, aesKey);
        String jwtString = jwtService.generateJwt(keyAlias);
        
        return resultModelsFactory.buildGenerateKeyResultModel(jwtString);
    }

    public SecretKey getKeyFromJwt(String jwtToken) throws Exception {
        String keyAlias = jwtService.getKeyAliasFromJwt(jwtToken);
        return keyStoreHelper.getKey(keyAlias);
    }
}
