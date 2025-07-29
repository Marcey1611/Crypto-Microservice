package com.projectwork.cryptoservice.boundary.validation.rule;

import com.projectwork.cryptoservice.boundary.validation.FieldName;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class NullOrBlankValidator {

    private final ErrorHandler errorHandler;

    /**
     * Validates that the given field is not null or empty.
     *
     * @param field The field to validate.
     * @param name  The name of the field, used for error messages.
     * @throws IllegalArgumentException if the field is null or empty.
     */
    public final void validateNullOrBlank(final String field, final FieldName name) {
        if (field == null || field.isBlank()) {
            final String fieldName = name.getValue();
            final String context = String.format("Field '%s' is blank", fieldName);
            throw this.errorHandler.handleError(context, fieldName, ErrorCode.FIELD_BLANK);
        }
    }
}
