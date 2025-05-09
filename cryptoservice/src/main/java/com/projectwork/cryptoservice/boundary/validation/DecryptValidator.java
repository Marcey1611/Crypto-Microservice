package com.projectwork.cryptoservice.boundary.validation;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class DecryptValidator extends BaseValidator {

    private final KeyStoreHelper keyStoreHelper;

    public void validateDecryptRequest(final DecryptRequest request) {
        final SecretKey jwtSigningKey = keyStoreHelper.getKey("jwt-signing-key");
        final String cipherText = request.getCipherText();
        final String jwt = request.getJwt();

        checkNotBlank(cipherText, "cipherText");
        checkMaxLength(cipherText, 2048, "cipherText");
        checkNoUnicodeEscapes(cipherText, "cipherText");

        checkNotBlank(jwt, "jwt");
        checkMaxLength(jwt, 4096, "jwt");
        checkJwt(jwt, jwtSigningKey);
    }
}
