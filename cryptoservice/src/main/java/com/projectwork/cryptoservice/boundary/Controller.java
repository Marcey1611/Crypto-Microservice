package com.projectwork.cryptoservice.boundary;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import com.projectwork.cryptoservice.boundary.api.DecryptAPI;
import com.projectwork.cryptoservice.boundary.api.EncryptAPI;
import com.projectwork.cryptoservice.boundary.api.JwtManagementAPI;
import com.projectwork.cryptoservice.boundary.api.KeyManagementAPI;
import com.projectwork.cryptoservice.boundary.api.TlsManagementAPI;
import com.projectwork.cryptoservice.boundary.validation.DecryptValidator;
import com.projectwork.cryptoservice.boundary.validation.EncryptValidator;
import com.projectwork.cryptoservice.boundary.validation.JwtManagementValidator;
import com.projectwork.cryptoservice.businessfacade.DecryptFacade;
import com.projectwork.cryptoservice.businessfacade.EncryptFacade;
import com.projectwork.cryptoservice.businessfacade.JwtManagementFacade;
import com.projectwork.cryptoservice.businessfacade.KeyManagementFacade;
import com.projectwork.cryptoservice.businessfacade.TlsManagementFacade;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResponse;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResponse;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResponse;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.GetRootCaCertResponse;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrRequest;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrResponse;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class Controller implements EncryptAPI, DecryptAPI, KeyManagementAPI, JwtManagementAPI, TlsManagementAPI {

    private final EncryptFacade encryptFacade;
    private final DecryptFacade decryptFacade;
    private final KeyManagementFacade keyManagementFacade;
    private final JwtManagementFacade jwtManagementFacade;
    private final TlsManagementFacade tlsManagementFacade;
    private final EncryptValidator encryptValidator;
    private final JwtManagementValidator jwtManagementValidator;
    private final DecryptValidator decryptValidator;

    @Override
    public ResponseEntity<EncryptResponse> encryptPost(final EncryptRequest encryptRequest, final Principal principal) {
        final String clientName = resolveClientName(principal);
        encryptValidator.validateEncryptRequest(encryptRequest);
        final ResponseEntity<EncryptResponse> encryptResponse = encryptFacade.processEncryption(encryptRequest, clientName);
        return encryptResponse;
    }

    @Override
    public ResponseEntity<DecryptResponse> decryptPost(final DecryptRequest decryptRequest, final Principal principal) {
        final String clientName = resolveClientName(principal);
        decryptValidator.validateDecryptRequest(decryptRequest);
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
        jwtManagementValidator.validateGenerateJwtRequest(generateJwtRequest);
        final ResponseEntity<GenerateJwtResponse> generateJwtResponse = jwtManagementFacade.generateJwt(generateJwtRequest, clientName);
        return generateJwtResponse;
    }

    // TODO delete after new implementation of mtls
    private String resolveClientName(final Principal principal) {
        if (principal != null) {
            return principal.getName();
        }
        return "anonymous-client";
    }

    // TODO delete after new implementation of mtls
    @Override
    public ResponseEntity<SignCsrResponse> signCsrPost(final SignCsrRequest signCsrRequest) {
        //validator.validateSignCsrRequest(signCsrRequest);
        final ResponseEntity<SignCsrResponse> signClientCertResponse = tlsManagementFacade.signCsr(signCsrRequest);
        return signClientCertResponse;
    }

    @Override
    public ResponseEntity<GetRootCaCertResponse> rootCaGet() {
        final ResponseEntity<GetRootCaCertResponse> rootCaCertResponse = tlsManagementFacade.getRootCaCert();
        return rootCaCertResponse;
    }
}