package com.projectwork.cryptoservice.boundary.validation;

import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

/**
 * EncryptValidator class for validating encryption requests.
 * This class checks the validity of the encryption request parameters and JWT.
 */
@Component
@RequiredArgsConstructor
public class EncryptValidator {

    private static final int PLAIN_TEXT_MAX_LENGTH = 2048;
    private static final int JWT_MAX_LENGTH = 4096;

    private final ValidationService validationService;
    private final KeyStoreHelper keyStoreHelper;

    /**
     * Validates the encryption request.
     *
     * @param request the EncryptRequest containing the plain text and JWT
     */
    public final void validateEncryptRequest(final EncryptRequest request) {
        final SecretKey key = this.keyStoreHelper.getKey("jwt-signing-key");
        final String plainText = request.getPlainText();
        this.validationService.validateText(plainText, FieldName.PLAIN_TEXT, PLAIN_TEXT_MAX_LENGTH, true);
        final String jwt = request.getJwt();
        this.validationService.validateText(jwt, FieldName.JWT, JWT_MAX_LENGTH, false);
        this.validationService.validateJwt(jwt, key);
    }
}