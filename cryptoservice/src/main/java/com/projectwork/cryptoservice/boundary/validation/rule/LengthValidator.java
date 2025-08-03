package com.projectwork.cryptoservice.boundary.validation.rule;

import com.projectwork.cryptoservice.boundary.validation.FieldName;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * LengthValidator class that validates the length of a given input string.
 * It throws an error if the input exceeds the specified maximum length.
 * SCPs:
 * - [6] All validation failures should result in input rejection
 * - [13] Validate data length
 */
@Component
@RequiredArgsConstructor
public class LengthValidator {

    private final ErrorHandler errorHandler;

    /**
     * Validates that the given input is within the specified length range.
     *
     * @param input the input to validate
     * @param maxLength the maximum allowed length for the input
     * @param name the name of the field being validated
     * @throws IllegalArgumentException if the input is null, empty, or outside the specified length range
     */
    public final void validateLength(final String input, final int maxLength, final FieldName name) {
        if (input.length() > maxLength) {
            final String fieldName = name.getValue();
            final String context = String.format("Field %s exceeds maximum allowed length of %s characters.", fieldName, maxLength);
            throw this.errorHandler.handleClientError(context, fieldName, ErrorCode.FIELD_TOO_LONG);
        }
    }
}
