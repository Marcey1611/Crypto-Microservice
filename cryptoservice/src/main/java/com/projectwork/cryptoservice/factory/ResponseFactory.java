package com.projectwork.cryptoservice.factory;

import com.projectwork.cryptoservice.entity.*;
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


}
