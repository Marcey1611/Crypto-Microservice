package com.projectwork.cryptoservice.boundary.validation;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;

@Component
public class EncryptValidator extends BaseValidator {

    @Autowired
    private KeyStoreHelper keyStoreHelper;

    public void validateEncryptRequest(final EncryptRequest encryptRequest) {
        final SecretKey jwtSigningKey = keyStoreHelper.getKey("jwt-signing-key");
        final String plainText = encryptRequest.getPlainText();
        final String jwt = encryptRequest.getJwt();

        checkNotBlank(plainText, "plainText");
        checkMaxLength(plainText, 2048, "plainText");
        checkNoUnicodeEscapes(plainText, "plainText");
        checkExtendedWhitelist(plainText, "plainText");

        checkNotBlank(jwt, "jwt");
        checkMaxLength(jwt, 4096, "jwt");
        checkJwt(jwt, jwtSigningKey);
    }
}
