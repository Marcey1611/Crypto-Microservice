package com.projectwork.cryptoservice.boundary.validation.rule;

import com.projectwork.cryptoservice.boundary.validation.FieldName;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * AsciiValidator class that validates if a given string contains only ASCII characters.
 * It throws an error if the string contains non-ASCII characters.
 *
 * SCPs:
 * - [4] Specify proper character sets, such as ASCII, for all sources of input
 * - [6] All validation failures should result in input rejection
 */
@Component
@RequiredArgsConstructor
public class AsciiValidator {

    private  final ErrorHandler errorHandler;

    /**
     * Validates that the given field contains only ASCII characters.
     *
     * @param field The field to validate.
     * @param name  The name of the field, used for error messages.
     * @throws IllegalArgumentException if the field contains non-ASCII characters.
     */
    public final void validateAscii(final String field, final FieldName name) {
        if (field == null || !field.chars().allMatch(c -> c < 128)) {
            final String fieldName = name.getValue();
            final String context = String.format("Field '%s' contains non-ASCII characters", name);
            throw this.errorHandler.handleError(context, fieldName, ErrorCode.INVALID_ASCII);
        }
    }
}
