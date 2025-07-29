package com.projectwork.cryptoservice.boundary.validation.rule;

import com.projectwork.cryptoservice.boundary.validation.FieldName;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Base64;

/**
 * Validates that the given input is a valid Base64 encoded string.
 *
 * SCPs:
 * - [6] All validation failures should result in input rejection
 */
@Component
@RequiredArgsConstructor
public class Base64Validator {

    private final ErrorHandler errorHandler;

    /**
     * Validates that the given input is a valid Base64 encoded string.
     *
     * @param input The input to validate.
     * @param name  The name of the input, used for error messages.
     * @throws IllegalArgumentException if the input is not a valid Base64 encoded string.
     */
    public void validateBase64(final String input, final FieldName name) {
        try {
            Base64.getDecoder().decode(input);
        } catch (IllegalArgumentException e) {
            final String fieldName = name.getValue();
            final String context = String.format("Field '%s' contains invalid Base64 characters", fieldName);
            throw this.errorHandler.handleError(context, fieldName, ErrorCode.INVALID_BASE64);
        }
    }
}
