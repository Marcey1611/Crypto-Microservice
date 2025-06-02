package com.projectwork.cryptoservice.boundary.validation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;

/**
 * Validator for JWT management requests, ensuring that the request parameters
 * meet the required criteria such as non-blank fields, maximum length,
 * and valid characters.
 */
@Component
public class JwtManagementValidator extends BaseValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtManagementValidator.class);
    private static final int ISSUED_TO_MAX_LENGTH = 64;

    /**
     * Validates the GenerateJwtRequest parameters.
     *
     * @param request the GenerateJwtRequest to validate
     */
    public final void validateGenerateJwtRequest(final GenerateJwtRequest request) {
        final String issuedTo = request.getIssuedTo();

        this.validateNotBlank(issuedTo, "issuedTo");
        this.validateMaxLength(issuedTo, ISSUED_TO_MAX_LENGTH, "issuedTo");
        this.validateNoUnicodeEscapes(issuedTo, "issuedTo");
        this.validateWhitelist(issuedTo, "issuedTo");
    }
}

