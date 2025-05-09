package com.projectwork.cryptoservice.entity.factory;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResultModel;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResultModel;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResultModel;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResultModel;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.GetRootCaCertResultModel;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrResultModel;

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

    // TODO delete after new implementation of mtls
    public SignCsrResultModel buildSignCsrResultModel(final String pemCert) {
        return new SignCsrResultModel(pemCert);
    }

    // TODO delete after new implementation of mtls
    public GetRootCaCertResultModel buildGetRootCaCertResultModel(final String rootCaCert) {
        return new GetRootCaCertResultModel(rootCaCert);
    }
}
