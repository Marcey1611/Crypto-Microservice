package com.projectwork.cryptoservice.businessfacade;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyManagementService;
import com.projectwork.cryptoservice.entity.factory.ModelsFactory;
import com.projectwork.cryptoservice.entity.factory.ResponseFactory;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyModel;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResultModel;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class KeyManagementFacade {
    private final KeyManagementService keyManagementService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    public ResponseEntity<GenerateKeyResponse> generateKey(final String clientName) {
        final GenerateKeyModel generateKeyModel = modelsFactory.buildGenerateKeyModel(clientName);
        final GenerateKeyResultModel generateKeyResultModel = keyManagementService.generateKey(generateKeyModel);
        return responseFactory.buildGenerateKeyResponse(generateKeyResultModel);
    }
}
