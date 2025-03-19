package com.projectwork.cryptoservice.businessfacade;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyManagementService;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;

@Service
public class KeyManagementFacade {
    private final KeyManagementService keyManagementService;

    public KeyManagementFacade(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    public GenerateKeyResultModel generateKey() throws Exception {
        
        return keyManagementService.generateKey();
    }

    public SecretKey getKeyFromJwt(String jwtToken) throws Exception {
        return keyManagementService.getKeyFromJwt(jwtToken);
    }
}
