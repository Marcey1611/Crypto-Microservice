package com.projectwork.cryptoservice.boundary.validation.rule;

import com.projectwork.cryptoservice.boundary.validation.FieldName;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * ControlCharValidator class that validates if a given string contains control characters.
 * It throws an error if the string contains any control characters.
 * SCPs:
 * - [6] All validation failures should result in input rejection
 */
@Component
@RequiredArgsConstructor
public class ControlCharValidator {

    private final ErrorHandler errorHandler;

    /**
     * Validates that the given input does not contain control characters.
     *
     * @param input The input to validate.
     * @param name  The name of the input, used for error messages.
     * @throws IllegalArgumentException if the input contains control characters.
     */
    public final void validateControlChars(final String input, final FieldName name) {
        if (input.chars().anyMatch(Character::isISOControl)) {
            final String fieldName = name.getValue();
            final String context = String.format("Field '%s' contains control characters.", name);
            throw this.errorHandler.handleClientError(context, fieldName, ErrorCode.CONTAINS_CONTROL_CHAR);
        }
    }
}
