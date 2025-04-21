package com.projectwork.cryptoservice.businessfacade;

import com.projectwork.cryptoservice.entity.encrypt.EncryptModel;
import com.projectwork.cryptoservice.entity.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResponse;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResultModel;
import com.projectwork.cryptoservice.factory.ModelsFactory;
import com.projectwork.cryptoservice.factory.ResponseFactory;
import com.projectwork.cryptoservice.businesslogic.EncryptService;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class EncryptFacade {

    private final EncryptService encryptService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    public EncryptFacade(final EncryptService encryptService, final ModelsFactory modelsFactory, final ResponseFactory responseFactory) {
        this.responseFactory = responseFactory;
        this.modelsFactory = modelsFactory;
        this.encryptService = encryptService;
    }

    public ResponseEntity<EncryptResponse> processEncryption(final EncryptRequest encryptRequest, final String clientName) {
        final EncryptModel encryptModel = modelsFactory.buildEncryptModel(encryptRequest, clientName);
        final EncryptResultModel encryptResultModel = encryptService.encrypt(encryptModel, clientName);
        return responseFactory.buildEncryptResponse(encryptResultModel);
    }
}
