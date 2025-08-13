package com.projectwork.cryptoservice.businessfacade;

import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyManagementService;
import com.projectwork.cryptoservice.entity.factory.ModelsFactory;
import com.projectwork.cryptoservice.entity.factory.ResponseFactory;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyModel;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResultModel;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

/**
 * KeyManagementFacade class that handles the key generation process.
 * It uses KeyManagementService to perform the generation and ModelsFactory to build the necessary models.
 */
@RequiredArgsConstructor
@Service
public class KeyManagementFacade {

    private final KeyManagementService keyManagementService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    /**
     * Generates a key for the specified client.
     *
     * @param clientName the name of the client for whom the key is being generated
     * @return a ResponseEntity containing the GenerateKeyResponse with the generated key
     */
    public final ResponseEntity<GenerateKeyResponse> generateKey(final String clientName) {
        final GenerateKeyModel generateKeyModel = this.modelsFactory.buildGenerateKeyModel(clientName);
        final GenerateKeyResultModel generateKeyResultModel = this.keyManagementService.generateKey(generateKeyModel);
        return this.responseFactory.buildGenerateKeyResponse(generateKeyResultModel);
    }
}
