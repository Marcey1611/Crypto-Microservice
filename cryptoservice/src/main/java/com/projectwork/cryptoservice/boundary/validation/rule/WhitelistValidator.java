package com.projectwork.cryptoservice.boundary.validation.rule;

import com.projectwork.cryptoservice.boundary.validation.FieldName;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
public class WhitelistValidator {

    private static final Pattern WHITELIST = Pattern.compile("^[a-zA-Z0-9 ._-]+$");
    private static final Pattern EXTENDED_WHITELIST = Pattern.compile("^[a-zA-Z0-9 .,;:!?@()\\[\\]{}\"'-]*$");

    private final ErrorHandler errorHandler;

    /**
     * Validates that the given field is in the whitelist.
     *
     * @param field The field to validate.
     * @param name  The name of the field, used for error messages.
     * @throws IllegalArgumentException if the field is not in the whitelist.
     */
    public final void validateWhitelist(final String field, final FieldName name, final boolean extended) {
        final Pattern pattern = extended ? EXTENDED_WHITELIST : WHITELIST;
        if (!pattern.matcher(field).matches()) {
            final String fieldName = name.getValue();
            final String context = String.format("Field '%s' contains invalid characters.", fieldName);
            throw this.errorHandler.handleError(context, fieldName, ErrorCode.ILLEGAL_CHARS);
        }
    }

}
