package com.projectwork.cryptoservice.businessfacade;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyManagementService;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyModel;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;
import com.projectwork.cryptoservice.factory.ModelsFactory;
import com.projectwork.cryptoservice.factory.ResponseFactory;

@Service
public class KeyManagementFacade {
    private final KeyManagementService keyManagementService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    public KeyManagementFacade(final KeyManagementService keyManagementService, final ModelsFactory modelsFactory, final ResponseFactory responseFactory) {
        this.responseFactory = responseFactory;
        this.modelsFactory = modelsFactory;
        this.keyManagementService = keyManagementService;
    }

    public ResponseEntity<GenerateKeyResponse> generateKey(final String clientName) {
        final GenerateKeyModel generateKeyModel = modelsFactory.buildGenerateKeyModel(clientName);
        final GenerateKeyResultModel generateKeyResultModel = keyManagementService.generateKey(generateKeyModel);
        return responseFactory.buildGenerateKeyResponse(generateKeyResultModel);
    }
}
