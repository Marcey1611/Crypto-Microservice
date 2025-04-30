package com.projectwork.cryptoservice.factory;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.decrypt.DecryptResultModel;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResultModel;
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

    public EncryptResultModel buildEncryptResultModel(final String cipherText) {
        return new EncryptResultModel(cipherText);
    }

    public DecryptResultModel buildDecryptResultModel(final String plainText) {
        return new DecryptResultModel(plainText);
    }
}
