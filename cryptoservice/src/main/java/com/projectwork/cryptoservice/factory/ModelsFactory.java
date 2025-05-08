package com.projectwork.cryptoservice.factory;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.decrypt.DecryptModel;
import com.projectwork.cryptoservice.entity.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.encrypt.EncryptModel;
import com.projectwork.cryptoservice.entity.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtModel;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyModel;
import com.projectwork.cryptoservice.entity.tlsmanagement.SignCsrModel;
import com.projectwork.cryptoservice.entity.tlsmanagement.SignCsrRequest;

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

    public SignCsrModel buildSignCsrModel(final SignCsrRequest signCsrRequest) {
        return new SignCsrModel(signCsrRequest.getCsrPem(), signCsrRequest.getClientName());
    }
}
