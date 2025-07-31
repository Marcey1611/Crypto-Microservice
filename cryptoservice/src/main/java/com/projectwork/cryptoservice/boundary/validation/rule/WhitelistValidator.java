package com.projectwork.cryptoservice.boundary.validation.rule;

import com.projectwork.cryptoservice.boundary.validation.FieldName;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * WhitelistValidator class that validates if a given string contains only allowed characters.
 * It throws an error if the string contains any characters not in the whitelist.
 *
 * SCPs:
 * - [6] All validation failures should result in input rejection
 * - [14] Validate all input against a "white" list of allowed characters, whenever possible
 */
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
            throw this.errorHandler.handleClientError(context, fieldName, ErrorCode.ILLEGAL_CHARS);
        }
    }

}
