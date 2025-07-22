package com.projectwork.cryptoservice.boundary.validation.rule;

import com.projectwork.cryptoservice.boundary.validation.FieldName;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

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
