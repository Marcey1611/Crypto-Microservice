package com.projectwork.cryptoservice.businessfacade;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.jwtmanagement.JwtManagementService;
import com.projectwork.cryptoservice.entity.factory.ModelsFactory;
import com.projectwork.cryptoservice.entity.factory.ResponseFactory;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtModel;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResponse;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResultModel;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class JwtManagementFacade {
    private final JwtManagementService jwtManagementService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    public ResponseEntity<GenerateJwtResponse> generateJwt(final GenerateJwtRequest generateJwtRequest, final String clientName) {
        final GenerateJwtModel generateJwtModel = modelsFactory.buildGenerateJwtModel(generateJwtRequest, clientName);
        final GenerateJwtResultModel generateJwtResultModel = jwtManagementService.generateJwt(generateJwtModel);
        return responseFactory.buildGenerateJwtResponse(generateJwtResultModel);
    }
    
}
