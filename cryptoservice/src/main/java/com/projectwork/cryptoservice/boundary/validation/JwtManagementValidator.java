package com.projectwork.cryptoservice.boundary.validation;

import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * JwtManagementValidator class for validating JWT management requests.
 * This class provides methods to validate the GenerateJwtRequest.
 */
@Component
@RequiredArgsConstructor
public class JwtManagementValidator {

    private static final int ISSUED_TO_MAX_LENGTH = 64;

    private final ValidationService validationService;

    /**
     * Validates the GenerateJwtRequest.
     *
     * @param request the GenerateJwtRequest containing the parameters for JWT generation
     */
    public final void validateGenerateJwtRequest(final GenerateJwtRequest request) {
        final String issuedTo = request.getIssuedTo();
        this.validationService.validateText(issuedTo, "issuedTo", ISSUED_TO_MAX_LENGTH, false);
    }
}