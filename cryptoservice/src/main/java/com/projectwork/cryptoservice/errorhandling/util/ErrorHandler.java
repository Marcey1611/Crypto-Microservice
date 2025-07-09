package com.projectwork.cryptoservice.errorhandling.util;

import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * ErrorHandler class that provides methods to handle validation errors
 * and log error details.
 * It uses the ErrorCode enum to build error details and logs them appropriately.
 */
@Service
public class ErrorHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ErrorHandler.class);

    /**
     * Handles validation errors by creating an ErrorDetail with the provided error code,
     * field name, and context, then logs the error and throws a BadRequestException.
     *
     * @param errorCode the ErrorCode representing the error
     * @param fieldName the name of the field that caused the validation error
     * @param context   additional context for the error
     * @return a BadRequestException containing the error details
     */
    public final RuntimeException handleValidationError(final ErrorCode errorCode, final String fieldName, final String context) {
        final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
        errorDetailBuilder.withUserMsgFormatted(fieldName);
        errorDetailBuilder.withLogMsgFormatted(fieldName);
        errorDetailBuilder.withContext(context);
        final ErrorDetail errorDetail = errorDetailBuilder.build();
        this.logError(errorDetail);
        return new BadRequestException(errorDetail);
    }

    /**
     * Handles validation errors by creating an ErrorDetail with the provided error code
     * and context, then logs the error and throws a BadRequestException.
     *
     * @param errorCode the ErrorCode representing the error
     * @param context   additional context for the error
     * @return a BadRequestException containing the error details
     */
    public final RuntimeException handleValidationError(final ErrorCode errorCode, final String context) {
        final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
        errorDetailBuilder.withContext(context);
        final ErrorDetail errorDetail = errorDetailBuilder.build();
        this.logError(errorDetail);
        return new BadRequestException(errorDetail);
    }

    /**
     * Logs the error details using the provided ErrorDetail object.
     *
     * @param errorDetail the ErrorDetail containing the error information
     */
    private void logError(final ErrorDetail errorDetail) {
        final String code = errorDetail.getCode();
        final String logHeadline = errorDetail.getLogHeadline();
        final String context = errorDetail.getContext();
        LOGGER.error("[{}] {}. {}", code, logHeadline, context);
    }
}
