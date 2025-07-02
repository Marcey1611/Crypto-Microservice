package com.projectwork.cryptoservice.businessfacade;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

/**
 * EncryptFacade class that handles the encryption process.
 * It uses EncryptService to perform the encryption and ModelsFactory to build the necessary models.
 */
@RequiredArgsConstructor
@Service
public class EncryptFacade {

    private static final Logger LOGGER = LoggerFactory.getLogger(EncryptFacade.class);

    private final EncryptService encryptService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    /**
     * Processes the encryption request.
     *
     * @param encryptRequest the request containing the plain text and JWT
     * @param clientName the name of the client making the request
     * @return a ResponseEntity containing the EncryptResponse with the encrypted cipher text
     */
    public final ResponseEntity<EncryptResponse> processEncryption(final EncryptRequest encryptRequest, final String clientName) {
        final EncryptModel encryptModel = this.modelsFactory.buildEncryptModel(encryptRequest, clientName);
        final EncryptResultModel encryptResultModel = this.encryptService.encrypt(encryptModel, clientName);
        return this.responseFactory.buildEncryptResponse(encryptResultModel);
    }
}
