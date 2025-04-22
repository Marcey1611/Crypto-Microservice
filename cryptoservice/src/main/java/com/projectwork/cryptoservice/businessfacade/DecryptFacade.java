package com.projectwork.cryptoservice.businessfacade;

import com.projectwork.cryptoservice.entity.decrypt.DecryptModel;
import com.projectwork.cryptoservice.entity.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.decrypt.DecryptResponse;
import com.projectwork.cryptoservice.entity.decrypt.DecryptResultModel;
import com.projectwork.cryptoservice.factory.ModelsFactory;
import com.projectwork.cryptoservice.factory.ResponseFactory;
import com.projectwork.cryptoservice.businesslogic.DecryptService;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class DecryptFacade {

    private final DecryptService decryptService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    public DecryptFacade(final DecryptService decryptService, final ModelsFactory modelsFactory, final ResponseFactory responseFactory) {
        this.decryptService = decryptService;
        this.modelsFactory = modelsFactory;
        this.responseFactory = responseFactory;
    }

    public ResponseEntity<DecryptResponse> processDecryption(final DecryptRequest decryptRequest, final String clientName) {
        final DecryptModel decryptModel = modelsFactory.buildDecryptModel(decryptRequest, clientName);
        final DecryptResultModel decryptResultModel = decryptService.decrypt(decryptModel, clientName);
        return responseFactory.buildDecryptResponse(decryptResultModel);
    }
}
