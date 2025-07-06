package com.projectwork.cryptoservice.boundary.validation;

import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
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

    /**
     * Validates the algorithm specified in the JWT header.
     *
     * @param alg The algorithm string to validate.
     * @throws BadRequestException if the algorithm is invalid or insecure.
     */
    public final void validateAlgorithmFromHeader(final String alg) {
        this.fieldValidator.validateNotBlank(alg, "algorithm (header)");
        this.fieldValidator.validateMaxLength(alg, MAX_LENGTH, "algorithm (header)");
        this.encodingValidator.validateNoUnicodeEscapes(alg, "algorithm (header)");
        this.fieldValidator.validateWhitelist(alg, "algorithm (header)");

        if ("none".equalsIgnoreCase(alg)) {
            final ErrorCode errorCode = ErrorCode.INSECURE_JWT_ALGO;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While validating JWT algorithm from header.");
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logError();
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Validates the key alias used in JWT operations.
     *
     * @param alias The key alias to validate.
     * @throws BadRequestException if the alias is blank, too long, contains Unicode escapes, or is not whitelisted.
     */
    public final void validateKeyAlias(final String alias) {
        this.fieldValidator.validateNotBlank(alias, "keyAlias");
        this.fieldValidator.validateMaxLength(alias, MAX_LENGTH, "keyAlias");
        this.encodingValidator.validateNoUnicodeEscapes(alias, "keyAlias");
        this.fieldValidator.validateWhitelist(alias, "keyAlias");
    }
}

