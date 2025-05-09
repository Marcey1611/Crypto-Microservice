package com.projectwork.cryptoservice.entity.factory;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.models.decrypt.DecryptModel;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptModel;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtModel;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyModel;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrModel;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrRequest;

@Component
public class ModelsFactory {

    public EncryptModel buildEncryptModel(final EncryptRequest encryptRequest, final String clientName) {
        return new EncryptModel(encryptRequest.getPlainText(), encryptRequest.getJwt(), clientName);
    }

    public DecryptModel buildDecryptModel(final DecryptRequest decryptRequest, final String clientName) {
        return new DecryptModel(decryptRequest.getCipherText(), decryptRequest.getJwt(), clientName);
    }

    public GenerateKeyModel buildGenerateKeyModel(final String clientNAme) {
        return new GenerateKeyModel(clientNAme);
    }

    public GenerateJwtModel buildGenerateJwtModel(final GenerateJwtRequest generateJwtRequest, final String clientName) {
        return new GenerateJwtModel(generateJwtRequest.getIssuedTo(), clientName);
    }

    // TODO delete after new implementation of mtls
    public SignCsrModel buildSignCsrModel(final SignCsrRequest signCsrRequest) {
        return new SignCsrModel(signCsrRequest.getCsrPem(), signCsrRequest.getClientName());
    }
}
