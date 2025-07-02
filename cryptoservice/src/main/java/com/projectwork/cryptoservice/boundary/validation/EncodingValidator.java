package com.projectwork.cryptoservice.boundary.validation;

import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import com.projectwork.cryptoservice.logging.CustomLogger;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Validator for checking the encoding of fields, specifically to ensure that they do not contain Unicode escape sequences.
 */
@Component
@RequiredArgsConstructor
public class EncodingValidator {

    private final CustomLogger customLogger;

    /**
     * Validates that the given field does not contain any Unicode escape sequences.
     *
     * @param field The field to validate.
     * @param name  The name of the field, used for error messages.
     * @throws BadRequestException if the field contains Unicode escape sequences.
     */
    public final void validateNoUnicodeEscapes(final String field, final String name) {
        if (field.contains("\\u")) {
            final ErrorCode errorCode = ErrorCode.INVALID_ENCODING;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withUserMsgFormatted(name);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            this.customLogger.logValidationError(errorDetail);
            throw new BadRequestException(errorDetail);
        }
    }
}
