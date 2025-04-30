package com.projectwork.cryptoservice.factory;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.decrypt.DecryptResponse;
import com.projectwork.cryptoservice.entity.decrypt.DecryptResultModel;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResponse;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResultModel;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtResponse;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtResultModel;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResultModel;

@Component
public class ResponseFactory {

    public ResponseEntity<EncryptResponse> buildEncryptResponse(EncryptResultModel encryptResultModel) {
        return ResponseEntity.ok(new EncryptResponse(encryptResultModel.getCipherText()));
    }

    public ResponseEntity<DecryptResponse> buildDecryptResponse(DecryptResultModel decryptResultModel) {
        return ResponseEntity.ok(new DecryptResponse(decryptResultModel.getPlainText()));
    }

    public ResponseEntity<GenerateKeyResponse> buildGenerateKeyResponse(final GenerateKeyResultModel generateKeyResultModel) {
        return ResponseEntity.ok(new GenerateKeyResponse(generateKeyResultModel.getMessage()));
    }

    public ResponseEntity<GenerateJwtResponse> buildGenerateJwtResponse(GenerateJwtResultModel generateJwtResultModel) {
        return ResponseEntity.ok(new GenerateJwtResponse(generateJwtResultModel.getJwt()));
    }

}
