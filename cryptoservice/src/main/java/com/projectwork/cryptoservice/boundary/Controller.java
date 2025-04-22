package com.projectwork.cryptoservice.boundary;

import com.projectwork.cryptoservice.entity.decrypt.DecryptModel;
import com.projectwork.cryptoservice.entity.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.decrypt.DecryptResponse;
import com.projectwork.cryptoservice.entity.decrypt.DecryptResultModel;
import com.projectwork.cryptoservice.entity.encrypt.EncryptModel;
import com.projectwork.cryptoservice.entity.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResponse;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResultModel;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtResponse;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyModel;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;
import com.projectwork.cryptoservice.entity.sign.SignModel;
import com.projectwork.cryptoservice.entity.sign.SignRequest;
import com.projectwork.cryptoservice.entity.sign.SignResponse;
import com.projectwork.cryptoservice.entity.sign.SignResultModel;
import com.projectwork.cryptoservice.entity.verify.VerifyModel;
import com.projectwork.cryptoservice.entity.verify.VerifyRequest;
import com.projectwork.cryptoservice.entity.verify.VerifyResponse;
import com.projectwork.cryptoservice.entity.verify.VerifyResultModel;
import com.projectwork.cryptoservice.factory.ModelsFactory;
import com.projectwork.cryptoservice.factory.ResponseFactory;
import com.projectwork.cryptoservice.validator.Validator;

import com.projectwork.cryptoservice.businessfacade.*;

import java.security.Principal;

import org.apache.catalina.connector.Response;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@org.springframework.stereotype.Controller
public class Controller implements EncryptAPI, DecryptAPI, /**SignAPI, VerifyAPI,**/ GenerateKeyAPI, GenerateJwtAPI {

    private final Validator validator;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;
    private final EncryptFacade encryptFacade;
    private final DecryptFacade decryptFacade;
    //private final SignFacade signFacade;
    //private final VerifyFacade verifyFacade;
    private final KeyManagementFacade keyManagementFacade;
    private final JwtManagementFacade jwtManagementFacade;

    public Controller(Validator validator, ModelsFactory modelsFactory, ResponseFactory responseFactory,
                            EncryptFacade encryptFacade, DecryptFacade decryptFacade,
                            SignFacade signFacade, VerifyFacade verifyFacade, KeyManagementFacade keyManagementFacade, JwtManagementFacade jwtManagementFacade) {
        this.jwtManagementFacade = jwtManagementFacade;
        this.validator = validator;
        this.modelsFactory = modelsFactory;
        this.responseFactory = responseFactory;
        this.encryptFacade = encryptFacade;
        this.decryptFacade = decryptFacade;
        //this.signFacade = signFacade;
        //this.verifyFacade = verifyFacade;
        this.keyManagementFacade = keyManagementFacade;
    }

    @Override
    public ResponseEntity<EncryptResponse> encryptPost(final EncryptRequest encryptRequest, final Principal principal) {
        validator.validateEncryptRequest(encryptRequest);
        ResponseEntity<EncryptResponse> encryptResponse = encryptFacade.processEncryption(encryptRequest, principal.getName());
        return encryptResponse;
    }

    @Override
    public ResponseEntity<DecryptResponse> decryptPost(final DecryptRequest decryptRequest, final Principal principal) {
        validator.validateDecryptRequest(decryptRequest);
        ResponseEntity<DecryptResponse> decryptResponse = decryptFacade.processDecryption(decryptRequest, principal.getName());
        return decryptResponse;
    }

    /**@Override
    public ResponseEntity<SignResponse> signPost(SignRequest signRequest) {
        validator.validateSignRequest(signRequest);
        SignModel signModel = modelsFactory.buildSignModel(signRequest);
        SignResultModel signResultModel = signFacade.processSigning(signModel);
        return responseFactory.buildSignResponse(signResultModel);
    }

    @Override
    public ResponseEntity<VerifyResponse> verifyPost(VerifyRequest verifyRequest) {
        validator.validateVerifyRequest(verifyRequest);
        VerifyModel verifyModel = modelsFactory.buildVerifyModel(verifyRequest);
        VerifyResultModel verifyResultModel = verifyFacade.processVerification(verifyModel);
        return responseFactory.buildVerifyResponse(verifyResultModel);
    }**/

    @Override
    public ResponseEntity<GenerateKeyResponse> generateKeyPost(Principal principal) {
        System.out.println("API `/keys/generate` wurde aufgerufen!");
        final GenerateKeyModel generateKeyModel = modelsFactory.buildGenerateKeyModel(principal.getName());
        System.out.println("Client Name: " + generateKeyModel.getClientName());

        try {
            GenerateKeyResultModel generateKeyResultModel = keyManagementFacade.generateKey(generateKeyModel);
            ResponseEntity<GenerateKeyResponse> generateKeyResponse = responseFactory.buildGenerateKeyResponse(generateKeyResultModel);
            return generateKeyResponse;
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @Override
    public ResponseEntity<GenerateJwtResponse> generateJwtPost(GenerateJwtRequest generateJwtRequest, Principal principal) {
        validator.validateGenerateJwtRequest(generateJwtRequest);
        ResponseEntity<GenerateJwtResponse> generateJwtResponse = jwtManagementFacade.generateJwt(generateJwtRequest, principal.getName());
        return generateJwtResponse;
    }

    
}
