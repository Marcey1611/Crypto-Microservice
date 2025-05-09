package com.projectwork.cryptoservice.entity.factory;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResponse;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResultModel;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResponse;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResultModel;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResponse;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResultModel;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResultModel;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.GetRootCaCertResponse;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.GetRootCaCertResultModel;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrResponse;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrResultModel;

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

    // TODO delete after new implementation of mtls
    public ResponseEntity<SignCsrResponse> buildSignCsrResponse(SignCsrResultModel signCsrResultModel) {
        return ResponseEntity.ok(new SignCsrResponse(signCsrResultModel.getPemCert()));
    }

    // TODO delete after new implementation of mtls
    public ResponseEntity<GetRootCaCertResponse> buildGetRootCaCertResponse(GetRootCaCertResultModel getRootCaCertResultModel) {
        return ResponseEntity.ok(new GetRootCaCertResponse(getRootCaCertResultModel.getRootCaCert()));
    }

}
