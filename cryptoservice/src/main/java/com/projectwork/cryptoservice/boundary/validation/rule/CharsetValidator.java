package com.projectwork.cryptoservice.boundary.validation.rule;

import com.projectwork.cryptoservice.boundary.validation.FieldName;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * CharsetValidator class that validates if a given string can be encoded in UTF-8.
 * It throws an error if the string contains characters that cannot be represented in UTF-8.
 * SCPs:
 * - [4] Specify proper character sets, such as UTF-8, for all sources of input
 * - [6] All validation failures should result in input rejection
 * - [121] Log all input validation failures
 */
@Component
@RequiredArgsConstructor
public class CharsetValidator {

    private final ErrorHandler errorHandler;

    /**
     * Validates that the given field is not null or empty.
     *
     * @param input The field to validate.
     * @param name  The name of the field, used for error messages.
     */
    public final void validateCharset(final String input, final FieldName name) {
        if (!StandardCharsets.UTF_8.newEncoder().canEncode(input)) {
            final String fieldName = name.getValue();
            final String context = String.format("Field '%s' cannot coded as UTF-8.", name);
            throw this.errorHandler.handleClientError(context, fieldName, ErrorCode.INVALID_CHARSET);
        }
    }
}
