package com.projectwork.cryptoservice.boundary;

import java.security.Principal;

import org.springframework.http.ResponseEntity;

import com.projectwork.cryptoservice.businessfacade.DecryptFacade;
import com.projectwork.cryptoservice.businessfacade.EncryptFacade;
import com.projectwork.cryptoservice.businessfacade.JwtManagementFacade;
import com.projectwork.cryptoservice.businessfacade.KeyManagementFacade;
import com.projectwork.cryptoservice.entity.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.decrypt.DecryptResponse;
import com.projectwork.cryptoservice.entity.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResponse;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtResponse;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.validator.Validator;

@org.springframework.stereotype.Controller
public class Controller implements EncryptAPI, DecryptAPI, GenerateKeyAPI, GenerateJwtAPI {

    private final Validator validator;
    private final EncryptFacade encryptFacade;
    private final DecryptFacade decryptFacade;
    private final KeyManagementFacade keyManagementFacade;
    private final JwtManagementFacade jwtManagementFacade;

    public Controller(final Validator validator, final EncryptFacade encryptFacade, final DecryptFacade decryptFacade,
                            final KeyManagementFacade keyManagementFacade, final JwtManagementFacade jwtManagementFacade) {
        this.jwtManagementFacade = jwtManagementFacade;
        this.validator = validator;
        this.encryptFacade = encryptFacade;
        this.decryptFacade = decryptFacade;
        this.keyManagementFacade = keyManagementFacade;
    }

    @Override
    public ResponseEntity<EncryptResponse> encryptPost(final EncryptRequest encryptRequest, final Principal principal) {
        validator.validateEncryptRequest(encryptRequest);
        final ResponseEntity<EncryptResponse> encryptResponse = encryptFacade.processEncryption(encryptRequest, principal.getName());
        return encryptResponse;
    }

    @Override
    public ResponseEntity<DecryptResponse> decryptPost(final DecryptRequest decryptRequest, final Principal principal) {
        validator.validateDecryptRequest(decryptRequest);
        final ResponseEntity<DecryptResponse> decryptResponse = decryptFacade.processDecryption(decryptRequest, principal.getName());
        return decryptResponse;
    }

    @Override
    public ResponseEntity<GenerateKeyResponse> generateKeyPost(final Principal principal) {
        final ResponseEntity<GenerateKeyResponse> generateKeyResponse = keyManagementFacade.generateKey(principal.getName());
        return generateKeyResponse;
    }

    @Override
    public ResponseEntity<GenerateJwtResponse> generateJwtPost(final GenerateJwtRequest generateJwtRequest, final Principal principal) {
        validator.validateGenerateJwtRequest(generateJwtRequest);
        final ResponseEntity<GenerateJwtResponse> generateJwtResponse = jwtManagementFacade.generateJwt(generateJwtRequest, principal.getName());
        return generateJwtResponse;
    }
}