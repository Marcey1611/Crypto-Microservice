package com.projectwork.cryptoservice.factory;

import com.projectwork.cryptoservice.entity.decrypt.DecryptModel;
import com.projectwork.cryptoservice.entity.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.encrypt.EncryptModel;
import com.projectwork.cryptoservice.entity.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtModel;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyModel;
import com.projectwork.cryptoservice.entity.sign.SignModel;
import com.projectwork.cryptoservice.entity.sign.SignRequest;
import com.projectwork.cryptoservice.entity.verify.VerifyModel;
import com.projectwork.cryptoservice.entity.verify.VerifyRequest;

import org.springframework.stereotype.Component;

@Component
public class ModelsFactory {

    public EncryptModel buildEncryptModel(final EncryptRequest encryptRequest, final String clientName) {
        return new EncryptModel(encryptRequest.getPlainText(), encryptRequest.getJwt(), clientName);
    }

    public DecryptModel buildDecryptModel(DecryptRequest decryptRequest) {
        return new DecryptModel(decryptRequest.getCipherText(), decryptRequest.getKey());
    }

    public SignModel buildSignModel(SignRequest signRequest) {
        return new SignModel();
    }

    public VerifyModel buildVerifyModel(VerifyRequest verifyRequest) {
        return new VerifyModel();
    }

    public GenerateKeyModel buildGenerateKeyModel(final String clientNAme) {
        return new GenerateKeyModel(clientNAme);
    }

    public GenerateJwtModel buildGenerateJwtModel(final GenerateJwtRequest generateJwtRequest, final String clientName) {
        return new GenerateJwtModel(generateJwtRequest.getIssuedTo(), clientName);
    }
}
