package com.projectwork.cryptoservice.boundary.validation;

import com.projectwork.cryptoservice.businesslogic.keymanagement.KeyStoreHelper;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

/**
 * DecryptValidator class for validating decryption requests.
 * This class checks the validity of the decryption request parameters and JWT.
 */
@Component
@RequiredArgsConstructor
public class DecryptValidator {

    private static final int JWT_MAX_LENGTH = 4096;
    private static final int CIPHER_TEXT_MAX_LENGTH = 2048;

    private final ValidationService validationService;
    private final KeyStoreHelper keyStoreHelper;

    /**
     * Validates the decryption request.
     *
     * @param request the DecryptRequest containing the cipher text and JWT
     */
    public final void validateDecryptRequest(final DecryptRequest request) {
        final SecretKey key = this.keyStoreHelper.getKey("jwt-signing-key");
        final String cipherText = request.getCipherText();
        this.validationService.validateTextWithoutWhitelist(cipherText, FieldName.CIPHER_TEXT, CIPHER_TEXT_MAX_LENGTH);
        final String jwt = request.getJwt();
        this.validationService.validateText(jwt, FieldName.JWT, JWT_MAX_LENGTH, false);
        this.validationService.validateJwt(jwt, key);
    }
}