package com.projectwork.cryptoservice.factory;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtResultModel;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;

@Component
public class ResultModelsFactory {
    
    public GenerateKeyResultModel buildGenerateKeyResultModel(final String message) {
        return new GenerateKeyResultModel(message);
    }

    public GenerateJwtResultModel buildGenerateJwtResultModel(final String jwt) {
        return new GenerateJwtResultModel(jwt);
    }
}
