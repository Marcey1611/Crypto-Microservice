package com.projectwork.cryptoservice.validator;

import com.projectwork.cryptoservice.entity.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.sign.SignRequest;
import com.projectwork.cryptoservice.entity.verify.VerifyRequest;

import org.springframework.stereotype.Component;

@Component
public class Validator {

    public void validateEncryptRequest(final EncryptRequest request) {
        
    }

    public void validateDecryptRequest(final DecryptRequest decryptRequest) {
        
    }

    public void validateSignRequest(final SignRequest signRequest) {
       
    }

    public void validateVerifyRequest(final VerifyRequest verifyRequest) {
        
    }

    public void validateGenerateJwtRequest(final GenerateJwtRequest generateJwtRequest) {
        
    }
}
