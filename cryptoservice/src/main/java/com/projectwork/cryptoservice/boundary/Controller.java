package com.projectwork.cryptoservice.boundary;

import com.projectwork.cryptoservice.entity.*;
import com.projectwork.cryptoservice.factory.ModelsFactory;
import com.projectwork.cryptoservice.factory.ResponseFactory;
import com.projectwork.cryptoservice.validator.Validator;
import com.projectwork.cryptoservice.businessfacade.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller implements EncryptAPI, DecryptAPI, SignAPI, VerifyAPI {

    private final Validator validator;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;
    private final EncryptFacade encryptFacade;
    private final DecryptFacade decryptFacade;
    private final SignFacade signFacade;
    private final VerifyFacade verifyFacade;

    public Controller(Validator validator, ModelsFactory modelsFactory, ResponseFactory responseFactory,
                            EncryptFacade encryptFacade, DecryptFacade decryptFacade,
                            SignFacade signFacade, VerifyFacade verifyFacade) {
        this.validator = validator;
        this.modelsFactory = modelsFactory;
        this.responseFactory = responseFactory;
        this.encryptFacade = encryptFacade;
        this.decryptFacade = decryptFacade;
        this.signFacade = signFacade;
        this.verifyFacade = verifyFacade;
    }

    @Override
    public ResponseEntity<EncryptResponse> encryptPost(EncryptRequest encryptRequest) {
        validator.validateEncryptRequest(encryptRequest);
        EncryptModel encryptModel = modelsFactory.buildEncryptModel(encryptRequest);
        EncryptResultModel encryptResultModel = encryptFacade.processEncryption(encryptModel);
        return responseFactory.buildEncryptResponse(encryptResultModel);
    }

    @Override
    public ResponseEntity<DecryptResponse> decryptPost(DecryptRequest decryptRequest) {
        validator.validateDecryptRequest(decryptRequest);
        DecryptModel decryptModel = modelsFactory.buildDecryptModel(decryptRequest);
        DecryptResultModel decryptResultModel = decryptFacade.processDecryption(decryptModel);
        return responseFactory.buildDecryptResponse(decryptResultModel);
    }

    @Override
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
    }
}
