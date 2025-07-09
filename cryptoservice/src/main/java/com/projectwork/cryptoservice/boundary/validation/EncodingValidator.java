package com.projectwork.cryptoservice.boundary.validation;

import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Validator for checking the encoding of fields, specifically to ensure that they do not contain Unicode escape sequences.
 */
@Component
@RequiredArgsConstructor
public class EncodingValidator {

    private final ErrorHandler errorHandler;

    /**
     * Validates that the given field does not contain any Unicode escape sequences.
     *
     * @param field The field to validate.
     * @param name  The name of the field, used for error messages.
     * @throws BadRequestException if the field contains Unicode escape sequences.
     */
    public final void validateNoUnicodeEscapes(final String field, final FieldName name) {
        if (field.contains("\\u")) {
            final String fieldName = name.getValue();
            final String context = String.format("While validating field: %s for Unicode escape sequences.", fieldName);
            throw this.errorHandler.handleValidationError(ErrorCode.INVALID_ENCODING, context, context);
        }
    }
}
