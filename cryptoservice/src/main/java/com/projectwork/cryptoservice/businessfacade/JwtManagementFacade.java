package com.projectwork.cryptoservice.businessfacade;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.jwtmanagement.JwtManagementService;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtModel;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtResponse;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtResultModel;
import com.projectwork.cryptoservice.factory.ModelsFactory;
import com.projectwork.cryptoservice.factory.ResponseFactory;

@Service
public class JwtManagementFacade {
    private final JwtManagementService jwtManagementService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    public JwtManagementFacade(final JwtManagementService jwtManagementService, final ModelsFactory modelsFactory, final ResponseFactory responseFactory) {
        this.responseFactory = responseFactory;
        this.modelsFactory = modelsFactory;
        this.jwtManagementService = jwtManagementService;
    }

    public ResponseEntity<GenerateJwtResponse> generateJwt(final GenerateJwtRequest generateJwtRequest, final String clientName) {
        final GenerateJwtModel generateJwtModel = modelsFactory.buildGenerateJwtModel(generateJwtRequest, clientName);
        // TODO cn abfrage
        final GenerateJwtResultModel generateJwtResultModel = jwtManagementService.generateJwt(generateJwtModel);
        return responseFactory.buildGenerateJwtResponse(generateJwtResultModel);
        //return jwtManagementService.generateJwt(generateJwtModel); TODO implement JwtManagementService
    }
    
}
