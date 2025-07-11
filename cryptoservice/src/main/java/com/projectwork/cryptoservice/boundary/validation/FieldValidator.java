package com.projectwork.cryptoservice.boundary.validation;

import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * FieldValidator is a component that provides methods to validate fields against various criteria,
 * such as being non-blank, having a maximum length, and matching specific character whitelists.
 */
@Component
@RequiredArgsConstructor
public class FieldValidator {

    private static final Pattern WHITELIST = Pattern.compile("^[a-zA-Z0-9 ._-]+$");
    private static final Pattern EXTENDED_WHITELIST = Pattern.compile("^[a-zA-Z0-9 .,;:!?@()\\[\\]{}\"'-]*$");

    private final ErrorHandler errorHandler;

    /**
     * Validates that the given field is not blank.
     *
     * @param field The field to validate.
     * @param name  The name of the field, used for error messages.
     * @throws BadRequestException if the field is blank.
     */
    public final void validateNotBlank(final String field, final FieldName name) {
        if (null == field || field.isBlank()) {
            final String fieldName = name.getValue();
            final String context = String.format("Field '%s' is blank", fieldName);
            throw this.errorHandler.handleError(context, fieldName, ErrorCode.FIELD_BLANK);
        }
    }

    /**
     * Validates that the given field does not exceed the specified maximum length.
     *
     * @param field      The field to validate.
     * @param maxLength  The maximum allowed length for the field.
     * @param name       The name of the field, used for error messages.
     * @throws BadRequestException if the field exceeds the maximum length.
     */
    public final void validateMaxLength(final String field, final int maxLength, final FieldName name) {
        if (field.length() > maxLength) {
            final String fieldName = name.getValue();
            final String context = String.format("Field %s exceeds maximum allowed length of %s characters.", fieldName, maxLength);
            throw this.errorHandler.handleError(context, fieldName, ErrorCode.FIELD_TOO_LONG);
        }
    }

    /**
     * Validates that the given field matches the specified whitelist pattern.
     *
     * @param field The field to validate.
     * @param name  The name of the field, used for error messages.
     * @throws BadRequestException if the field contains illegal characters.
     */
    public final void validateWhitelist(final String field, final FieldName name) {
        final Matcher matcher = WHITELIST.matcher(field);
        if (!matcher.matches()) {
            final String fieldName = name.getValue();
            final String context = String.format("While validating field: %s against whitelist.", fieldName);
            throw this.errorHandler.handleError(context, fieldName, ErrorCode.ILLEGAL_CHARS);
        }
    }

    /**
     * Validates that the given field matches the extended whitelist pattern.
     *
     * @param field The field to validate.
     * @param name  The name of the field, used for error messages.
     * @throws BadRequestException if the field contains illegal characters.
     */
    public final void validateExtendedWhitelist(final String field, final FieldName name) {
        final Matcher matcher = EXTENDED_WHITELIST.matcher(field);
        if (!matcher.matches()) {
            final String fieldName = name.getValue();
            final String context = String.format("While validating field: %s against extended whitelist.", fieldName);
            throw this.errorHandler.handleError(context, fieldName, ErrorCode.ILLEGAL_CHARS);
        }
    }
}
