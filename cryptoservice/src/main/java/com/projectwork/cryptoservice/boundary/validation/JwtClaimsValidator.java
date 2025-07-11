package com.projectwork.cryptoservice.boundary.validation;

import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * JwtClaimsValidator is a component that validates JWT claims, specifically the algorithm from the header
 * and the key alias used in JWT operations.
 */
@Component
@RequiredArgsConstructor
public class JwtClaimsValidator {


    private static final int MAX_LENGTH = 64;

    private final FieldValidator fieldValidator;
    private final EncodingValidator encodingValidator;
    private final ErrorHandler errorHandler;

    /**
     * Validates the algorithm specified in the JWT header.
     *
     * @param alg The algorithm string to validate.
     * @throws BadRequestException if the algorithm is invalid or insecure.
     */
    public final void validateAlgorithmFromHeader(final String alg) {
        this.fieldValidator.validateNotBlank(alg, FieldName.ALGORITHM_HEADER);
        this.fieldValidator.validateMaxLength(alg, MAX_LENGTH, FieldName.ALGORITHM_HEADER);
        this.encodingValidator.validateNoUnicodeEscapes(alg, FieldName.ALGORITHM_HEADER);
        this.fieldValidator.validateWhitelist(alg, FieldName.ALGORITHM_HEADER);

        if ("none".equalsIgnoreCase(alg)) {
            throw this.errorHandler.handleError(ErrorCode.INSECURE_JWT_ALGO, "While validating JWT algorithm from header.");
        }
    }

    /**
     * Validates the key alias used in JWT operations.
     *
     * @param alias The key alias to validate.
     * @throws BadRequestException if the alias is blank, too long, contains Unicode escapes, or is not whitelisted.
     */
    public final void validateKeyAlias(final String alias) {
        this.fieldValidator.validateNotBlank(alias, FieldName.KEY_ALIAS);
        this.fieldValidator.validateMaxLength(alias, MAX_LENGTH, FieldName.KEY_ALIAS);
        this.encodingValidator.validateNoUnicodeEscapes(alias, FieldName.KEY_ALIAS);
        this.fieldValidator.validateWhitelist(alias, FieldName.KEY_ALIAS);
    }
}

