package com.projectwork.cryptoservice.boundary.validation;

import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import com.projectwork.cryptoservice.logging.CustomLogger;
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

    private final CustomLogger customLogger;

    private static final Pattern WHITELIST = Pattern.compile("^[a-zA-Z0-9 ._-]+$");
    private static final Pattern EXTENDED_WHITELIST = Pattern.compile("^[a-zA-Z0-9 .,;:!?@()\\[\\]{}\"'-]*$");

    /**
     * Validates that the given field is not blank.
     *
     * @param field The field to validate.
     * @param name  The name of the field, used for error messages.
     * @throws BadRequestException if the field is blank.
     */
    public final void validateNotBlank(final String field, final String name) {
        if (null == field || field.isBlank()) {
            final ErrorCode errorCode = ErrorCode.FIELD_BLANK;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withUserMsgFormatted(name);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            this.customLogger.logError(errorDetail);
            throw new BadRequestException(errorDetail);
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
    public final void validateMaxLength(final String field, final int maxLength, final String name) {
        if (field.length() > maxLength) {
            final ErrorCode errorCode = ErrorCode.FIELD_TOO_LONG;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withUserMsgFormatted(name);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            this.customLogger.logError(errorDetail);
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Validates that the given field matches the specified whitelist pattern.
     *
     * @param field The field to validate.
     * @param name  The name of the field, used for error messages.
     * @throws BadRequestException if the field contains illegal characters.
     */
    public final void validateWhitelist(final String field, final String name) {
        final Matcher matcher = WHITELIST.matcher(field);
        if (!matcher.matches()) {
            final ErrorCode errorCode = ErrorCode.ILLEGAL_CHARS;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withUserMsgFormatted(name);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            this.customLogger.logError(errorDetail);
            throw new BadRequestException(errorDetail);
        }
    }

    /**
     * Validates that the given field matches the extended whitelist pattern.
     *
     * @param field The field to validate.
     * @param name  The name of the field, used for error messages.
     * @throws BadRequestException if the field contains illegal characters.
     */
    public final void validateExtendedWhitelist(final String field, final String name) {
        final Matcher matcher = EXTENDED_WHITELIST.matcher(field);
        if (!matcher.matches()) {
            final ErrorCode errorCode = ErrorCode.ILLEGAL_CHARS;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withUserMsgFormatted(name);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            this.customLogger.logError(errorDetail);
            throw new BadRequestException(errorDetail);
        }
    }
}
