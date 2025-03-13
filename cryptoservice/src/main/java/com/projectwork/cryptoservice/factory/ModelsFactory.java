package com.projectwork.cryptoservice.factory;

import com.projectwork.cryptoservice.entity.*;
import org.springframework.stereotype.Component;

@Component
public class ModelsFactory {

    public EncryptModel buildEncryptModel(EncryptRequest encryptRequest) {
        return new EncryptModel(encryptRequest.getPlainText(), encryptRequest.getKey());
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
}
