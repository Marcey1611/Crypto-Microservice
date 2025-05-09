package com.projectwork.cryptoservice.businessfacade;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.DecryptService;
import com.projectwork.cryptoservice.entity.factory.ModelsFactory;
import com.projectwork.cryptoservice.entity.factory.ResponseFactory;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptModel;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResponse;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResultModel;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class DecryptFacade {
    private final DecryptService decryptService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    public ResponseEntity<DecryptResponse> processDecryption(final DecryptRequest decryptRequest, final String clientName) {
        final DecryptModel decryptModel = modelsFactory.buildDecryptModel(decryptRequest, clientName);
        final DecryptResultModel decryptResultModel = decryptService.decrypt(decryptModel, clientName);
        return responseFactory.buildDecryptResponse(decryptResultModel);
    }
}
