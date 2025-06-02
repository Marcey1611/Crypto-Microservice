package com.projectwork.cryptoservice.boundary.validation;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;

import lombok.RequiredArgsConstructor;

/**
 * Validator for encrypt requests, ensuring that the request parameters
 * meet the required criteria such as non-blank fields, maximum length,
 * and valid JWT format.
 */
@RequiredArgsConstructor
@Component
public class EncryptValidator extends BaseValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(EncryptValidator.class);
    private static final int PLAIN_TEXT_MAX_LENGTH = 2048;
    private static final int JWT_MAX_LENGTH = 4096;

    private final KeyStoreHelper keyStoreHelper;

    /**
     * Validates the encrypt request parameters.
     *
     * @param encryptRequest the encrypt request to validate
     */
    public final void validateEncryptRequest(final EncryptRequest encryptRequest) {
        final SecretKey jwtSigningKey = this.keyStoreHelper.getKey("jwt-signing-key");
        final String plainText = encryptRequest.getPlainText();
        final String jwt = encryptRequest.getJwt();

        this.validateNotBlank(plainText, "plainText");
        this.validateMaxLength(plainText, PLAIN_TEXT_MAX_LENGTH, "plainText");
        this.validateNoUnicodeEscapes(plainText, "plainText");
        this.validateExtendedWhitelist(plainText, "plainText");

        this.validateNotBlank(jwt, "jwt");
        this.validateMaxLength(jwt, JWT_MAX_LENGTH, "jwt");
        this.validateJwt(jwt, jwtSigningKey);
    }
}
