package com.projectwork.cryptoservice.validator;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.tlsmanagement.SignCsrRequest;

@Component
public class Validator {

    public void validateEncryptRequest(final EncryptRequest request) {
        // TODO Implement validation logic for EncryptRequest
    }

    public void validateDecryptRequest(final DecryptRequest decryptRequest) {
        // TODO Implement validation logic for DecryptRequest
    }

    public void validateGenerateJwtRequest(final GenerateJwtRequest generateJwtRequest) {
        // TODO Implement validation logic for GenerateJwtRequest
    }

    public void validateSignCsrRequest(final SignCsrRequest signCsrRequest) {
        // TODO Implement validation logic for SignClientCertRequest
    }
}
