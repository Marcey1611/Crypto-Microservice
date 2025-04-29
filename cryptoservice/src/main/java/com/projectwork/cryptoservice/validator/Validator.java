package com.projectwork.cryptoservice.validator;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtRequest;

@Component
public class Validator {

    public void validateEncryptRequest(final EncryptRequest request) {
        
    }

    public void validateDecryptRequest(final DecryptRequest decryptRequest) {
        
    }

    public void validateGenerateJwtRequest(final GenerateJwtRequest generateJwtRequest) {
        
    }
}
