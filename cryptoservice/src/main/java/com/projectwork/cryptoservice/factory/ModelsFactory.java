package com.projectwork.cryptoservice.factory;

import com.projectwork.cryptoservice.entity.decrypt.DecryptModel;
import com.projectwork.cryptoservice.entity.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.encrypt.EncryptModel;
import com.projectwork.cryptoservice.entity.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.sign.SignModel;
import com.projectwork.cryptoservice.entity.sign.SignRequest;
import com.projectwork.cryptoservice.entity.verify.VerifyModel;
import com.projectwork.cryptoservice.entity.verify.VerifyRequest;

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
