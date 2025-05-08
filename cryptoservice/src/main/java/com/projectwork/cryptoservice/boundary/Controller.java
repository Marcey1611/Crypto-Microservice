package com.projectwork.cryptoservice.boundary;

import java.security.Principal;

import org.springframework.http.ResponseEntity;

import com.projectwork.cryptoservice.businessfacade.DecryptFacade;
import com.projectwork.cryptoservice.businessfacade.EncryptFacade;
import com.projectwork.cryptoservice.businessfacade.JwtManagementFacade;
import com.projectwork.cryptoservice.businessfacade.KeyManagementFacade;
import com.projectwork.cryptoservice.businessfacade.TlsManagementFacade;
import com.projectwork.cryptoservice.entity.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.decrypt.DecryptResponse;
import com.projectwork.cryptoservice.entity.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResponse;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtResponse;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.entity.tlsmanagement.GetRootCaCertResponse;
import com.projectwork.cryptoservice.entity.tlsmanagement.SignCsrRequest;
import com.projectwork.cryptoservice.entity.tlsmanagement.SignCsrResponse;
import com.projectwork.cryptoservice.validator.Validator;

@org.springframework.stereotype.Controller
public class Controller implements EncryptAPI, DecryptAPI, GenerateKeyAPI, GenerateJwtAPI, TlsManagementAPI {

    private final Validator validator;
    private final EncryptFacade encryptFacade;
    private final DecryptFacade decryptFacade;
    private final KeyManagementFacade keyManagementFacade;
    private final JwtManagementFacade jwtManagementFacade;
    private final TlsManagementFacade tlsManagementFacade;

    public Controller(final Validator validator, final EncryptFacade encryptFacade, final DecryptFacade decryptFacade,
                            final KeyManagementFacade keyManagementFacade, final JwtManagementFacade jwtManagementFacade, final TlsManagementFacade tlsManagementFacade) {
        this.jwtManagementFacade = jwtManagementFacade;
        this.validator = validator;
        this.encryptFacade = encryptFacade;
        this.decryptFacade = decryptFacade;
        this.keyManagementFacade = keyManagementFacade;
        this.tlsManagementFacade = tlsManagementFacade;
    }

    @Override
    public ResponseEntity<EncryptResponse> encryptPost(final EncryptRequest encryptRequest, final Principal principal) {
        final String clientName = resolveClientName(principal);
        validator.validateEncryptRequest(encryptRequest);
        final ResponseEntity<EncryptResponse> encryptResponse = encryptFacade.processEncryption(encryptRequest, clientName);
        return encryptResponse;
    }

    @Override
    public ResponseEntity<DecryptResponse> decryptPost(final DecryptRequest decryptRequest, final Principal principal) {
        final String clientName = resolveClientName(principal);
        validator.validateDecryptRequest(decryptRequest);
        final ResponseEntity<DecryptResponse> decryptResponse = decryptFacade.processDecryption(decryptRequest, clientName);
        return decryptResponse;
    }

    @Override
    public ResponseEntity<GenerateKeyResponse> generateKeyPost(final Principal principal) {
        final String clientName = resolveClientName(principal);
        final ResponseEntity<GenerateKeyResponse> generateKeyResponse = keyManagementFacade.generateKey(clientName);
        return generateKeyResponse;
    }

    @Override
    public ResponseEntity<GenerateJwtResponse> generateJwtPost(final GenerateJwtRequest generateJwtRequest, final Principal principal) {
        final String clientName = resolveClientName(principal);
        validator.validateGenerateJwtRequest(generateJwtRequest);
        final ResponseEntity<GenerateJwtResponse> generateJwtResponse = jwtManagementFacade.generateJwt(generateJwtRequest, clientName);
        return generateJwtResponse;
    }

    // TODO remove after mtls implementation
    private String resolveClientName(final Principal principal) {
        if (principal != null) {
            return principal.getName();
        }
        return "anonymous-client";
    }

    // TODO remove after external mtls implementation
    @Override
    public ResponseEntity<SignCsrResponse> signCsrPost(final SignCsrRequest signCsrRequest) {
        validator.validateSignCsrRequest(signCsrRequest);
        final ResponseEntity<SignCsrResponse> signClientCertResponse = tlsManagementFacade.signCsr(signCsrRequest);
        return signClientCertResponse;
    }

    @Override
    public ResponseEntity<GetRootCaCertResponse> rootCaGet() {
        final ResponseEntity<GetRootCaCertResponse> rootCaCertResponse = tlsManagementFacade.getRootCaCert();
        return rootCaCertResponse;
    }
    
}