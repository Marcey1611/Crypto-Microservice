package com.projectwork.cryptoservice.factory;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;

@Component
public class ResultModelsFactory {
    
    public GenerateKeyResultModel buildGenerateKeyResultModel(final String jwString) {
        return new GenerateKeyResultModel(jwString);
    }
}
