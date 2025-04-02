package com.projectwork.cryptoservice.factory;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;

@Component
public class ResultModelsFactory {
    
    public GenerateKeyResultModel buildGenerateKeyResultModel() {
        return new GenerateKeyResultModel();
    }
}
