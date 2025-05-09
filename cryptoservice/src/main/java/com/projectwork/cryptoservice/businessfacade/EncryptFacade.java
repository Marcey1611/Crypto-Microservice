package com.projectwork.cryptoservice.businessfacade;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.EncryptService;
import com.projectwork.cryptoservice.entity.factory.ModelsFactory;
import com.projectwork.cryptoservice.entity.factory.ResponseFactory;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptModel;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResponse;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResultModel;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class EncryptFacade {
    private final EncryptService encryptService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    public ResponseEntity<EncryptResponse> processEncryption(final EncryptRequest encryptRequest, final String clientName) {
        final EncryptModel encryptModel = modelsFactory.buildEncryptModel(encryptRequest, clientName);
        final EncryptResultModel encryptResultModel = encryptService.encrypt(encryptModel, clientName);
        return responseFactory.buildEncryptResponse(encryptResultModel);
    }
}
