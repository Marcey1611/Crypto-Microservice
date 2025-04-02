package com.projectwork.cryptoservice.factory;

import com.projectwork.cryptoservice.entity.decrypt.DecryptResponse;
import com.projectwork.cryptoservice.entity.decrypt.DecryptResultModel;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResponse;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResultModel;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;
import com.projectwork.cryptoservice.entity.sign.SignResponse;
import com.projectwork.cryptoservice.entity.sign.SignResultModel;
import com.projectwork.cryptoservice.entity.verify.VerifyResponse;
import com.projectwork.cryptoservice.entity.verify.VerifyResultModel;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component
public class ResponseFactory {

    public ResponseEntity<EncryptResponse> buildEncryptResponse(EncryptResultModel encryptResultModel) {
        return ResponseEntity.ok(new EncryptResponse(encryptResultModel.getCipherText()));
    }

    public ResponseEntity<DecryptResponse> buildDecryptResponse(DecryptResultModel decryptResultModel) {
        return ResponseEntity.ok(new DecryptResponse(decryptResultModel.getPlainText()));
    }

    public ResponseEntity<SignResponse> buildSignResponse(SignResultModel signResultModel) {
        return ResponseEntity.ok(new SignResponse(signResultModel.getSignature()));
    }

    public ResponseEntity<VerifyResponse> buildVerifyResponse(VerifyResultModel verifyResultModel) {
        return ResponseEntity.ok(new VerifyResponse(verifyResultModel.getVerified()));
    }

    public ResponseEntity<GenerateKeyResponse> buildGenerateKeyResponse(GenerateKeyResultModel generateKeyResultModel) {
        return ResponseEntity.ok(new GenerateKeyResponse(generateKeyResultModel.getMessage()));
    }

}
