package com.projectwork.cryptoservice.boundary.validation;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;

import lombok.RequiredArgsConstructor;

/**
 * Validator for decrypt requests, ensuring that the request parameters
 * meet the required criteria such as non-blank fields, maximum length,
 * and valid JWT format.
 */
@RequiredArgsConstructor
@Component
public class DecryptValidator extends BaseValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptValidator.class);

    private static final int CIPHER_TEXT_MAX_LENGTH = 2048;
    private static final int JWT_MAX_LENGTH = 4096;
    private final KeyStoreHelper keyStoreHelper;

    /**
     * Validates the decrypt request parameters.
     *
     * @param request the decrypt request to validate
     */
    public final void validateDecryptRequest(final DecryptRequest request) {
        final SecretKey jwtSigningKey = this.keyStoreHelper.getKey("jwt-signing-key");
        final String cipherText = request.getCipherText();
        final String jwt = request.getJwt();

        this.validateNotBlank(cipherText, "cipherText");
        this.validateMaxLength(cipherText, CIPHER_TEXT_MAX_LENGTH, "cipherText");
        this.validateNoUnicodeEscapes(cipherText, "cipherText");

        this.validateNotBlank(jwt, "jwt");
        this.validateMaxLength(jwt, JWT_MAX_LENGTH, "jwt");
        this.validateJwt(jwt, jwtSigningKey);
    }
}
