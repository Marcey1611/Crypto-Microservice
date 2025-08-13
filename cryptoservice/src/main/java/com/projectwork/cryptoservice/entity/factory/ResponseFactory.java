package com.projectwork.cryptoservice.entity.factory;

import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResponse;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResultModel;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResponse;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResultModel;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResponse;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResultModel;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResultModel;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

/**
 * ResponseFactory class that builds various response entities
 */
@Component
public class ResponseFactory {

    /**
     * Builds a response entity for encryption results.
     *
     * @param encryptResultModel the model containing the encryption result
     * @return a ResponseEntity containing the EncryptResponse
     */
    public final ResponseEntity<EncryptResponse> buildEncryptResponse(final EncryptResultModel encryptResultModel) {
        final String cipherText = encryptResultModel.getCipherText();
        return ResponseEntity.ok(new EncryptResponse(cipherText));
    }

    /**
     * Builds a response entity for decryption results.
     *
     * @param decryptResultModel the model containing the decryption result
     * @return a ResponseEntity containing the DecryptResponse
     */
    public final ResponseEntity<DecryptResponse> buildDecryptResponse(final DecryptResultModel decryptResultModel) {
        final String plainText = decryptResultModel.getPlainText();
        return ResponseEntity.ok(new DecryptResponse(plainText));
    }

    /**
     * Builds a response entity for key generation results.
     *
     * @param generateKeyResultModel the model containing the key generation result
     * @return a ResponseEntity containing the GenerateKeyResponse
     */
    public final ResponseEntity<GenerateKeyResponse> buildGenerateKeyResponse(final GenerateKeyResultModel generateKeyResultModel) {
        final String message = generateKeyResultModel.getMessage();
        return ResponseEntity.ok(new GenerateKeyResponse(message));
    }

    /**
     * Builds a response entity for JWT generation results.
     *
     * @param generateJwtResultModel the model containing the JWT generation result
     * @return a ResponseEntity containing the GenerateJwtResponse
     */
    public final ResponseEntity<GenerateJwtResponse> buildGenerateJwtResponse(final GenerateJwtResultModel generateJwtResultModel) {
        final String jwt = generateJwtResultModel.getJwt();
        return ResponseEntity.ok(new GenerateJwtResponse(jwt));
    }
}
