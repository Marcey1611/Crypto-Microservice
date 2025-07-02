package com.projectwork.cryptoservice.businessfacade;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

/**
 * DecryptFacade class that handles the decryption process.
 * It uses DecryptService to perform the decryption and ModelsFactory to build the necessary models.
 */
@RequiredArgsConstructor
@Service
public class DecryptFacade {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptFacade.class);

    private final DecryptService decryptService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    /**
     * Processes the decryption request.
     *
     * @param decryptRequest the request containing the cipher text and JWT
     * @param clientName the name of the client making the request
     * @return a ResponseEntity containing the DecryptResponse with the decrypted plain text
     */
    public final ResponseEntity<DecryptResponse> processDecryption(final DecryptRequest decryptRequest, final String clientName) {
        final DecryptModel decryptModel = this.modelsFactory.buildDecryptModel(decryptRequest, clientName);
        final DecryptResultModel decryptResultModel = this.decryptService.decrypt(decryptModel, clientName);
        return this.responseFactory.buildDecryptResponse(decryptResultModel);
    }
}
