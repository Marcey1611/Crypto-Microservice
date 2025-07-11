package com.projectwork.cryptoservice.businessfacade;

import com.projectwork.cryptoservice.businesslogic.jwtmanagement.JwtManagementService;
import com.projectwork.cryptoservice.entity.factory.ModelsFactory;
import com.projectwork.cryptoservice.entity.factory.ResponseFactory;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtModel;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResponse;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResultModel;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

/**
 * JwtManagementFacade class that handles the JWT generation process.
 * It uses JwtManagementService to perform the generation and ModelsFactory to build the necessary models.
 */
@RequiredArgsConstructor
@Service
public class JwtManagementFacade {

    private final JwtManagementService jwtManagementService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    /**
     * Generates a JWT based on the provided request and client name.
     *
     * @param generateJwtRequest the request containing the parameters for JWT generation
     * @param clientName the name of the client making the request
     * @return a ResponseEntity containing the GenerateJwtResponse with the generated JWT
     */
    public final ResponseEntity<GenerateJwtResponse> generateJwt(final GenerateJwtRequest generateJwtRequest, final String clientName) {
        final GenerateJwtModel generateJwtModel = this.modelsFactory.buildGenerateJwtModel(generateJwtRequest, clientName);
        final GenerateJwtResultModel generateJwtResultModel = this.jwtManagementService.generateJwt(generateJwtModel);
        return this.responseFactory.buildGenerateJwtResponse(generateJwtResultModel);
    }
    
}
