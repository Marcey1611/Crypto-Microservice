package com.projectwork.cryptoservice.factory;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.decrypt.DecryptResultModel;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResultModel;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtResultModel;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;
import com.projectwork.cryptoservice.entity.tlsmanagement.GetRootCaCertResponse;
import com.projectwork.cryptoservice.entity.tlsmanagement.GetRootCaCertResultModel;
import com.projectwork.cryptoservice.entity.tlsmanagement.SignCsrResultModel;

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

    public SignCsrResultModel buildSignCsrResultModel(final String pemCert) {
        return new SignCsrResultModel(pemCert);
    }

    public GetRootCaCertResultModel buildGetRootCaCertResultModel(final String rootCaCert) {
        return new GetRootCaCertResultModel(rootCaCert);
    }
}
