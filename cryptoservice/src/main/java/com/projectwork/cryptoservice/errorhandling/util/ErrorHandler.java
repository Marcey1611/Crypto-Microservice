package com.projectwork.cryptoservice.errorhandling.util;

import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
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
     * Handles an error by creating an ErrorDetail object, logging it,
     * and throwing an InternalServerErrorException.
     *
     * @param errorCode         the ErrorCode representing the error
     * @param logMsgExtension   additional message to be included in the log
     * @param context           context information about where the error occurred
     * @param exception         the exception that caused the error
     * @return a RuntimeException (InternalServerErrorException) with the error details
     */
    public final RuntimeException handleError(final ErrorCode errorCode, final String logMsgExtension, final String context, final Throwable exception) {
        final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
        errorDetailBuilder.withLogMsgFormatted(logMsgExtension);
        errorDetailBuilder.withContext(context);
        errorDetailBuilder.withException(exception);
        final ErrorDetail errorDetail = errorDetailBuilder.build();
        this.logError(errorDetail);
        throw new InternalServerErrorException(errorDetail);
    }

    /**
     * Handles an error by creating an ErrorDetail object, logging it,
     * and throwing an InternalServerErrorException.
     *
     * @param errorCode the ErrorCode representing the error
     * @param context   context information about where the error occurred
     * @param exception the exception that caused the error
     * @return a RuntimeException (InternalServerErrorException) with the error details
     */
    public final RuntimeException handleError(final ErrorCode errorCode, final String context, final Throwable exception) {
        final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
        errorDetailBuilder.withContext(context);
        errorDetailBuilder.withException(exception);
        final ErrorDetail errorDetail = errorDetailBuilder.build();
        this.logError(errorDetail);
        throw new InternalServerErrorException(errorDetail);
    }

    /**
     * Handles an error by creating an ErrorDetail object, logging it,
     * and throwing a BadRequestException.
     *
     * @param errorCode the ErrorCode representing the error
     * @param exception the exception that caused the error
     * @param context   context information about where the error occurred
     * @return a RuntimeException (BadRequestException) with the error details
     */
    public final RuntimeException handleError(final ErrorCode errorCode, final Throwable exception, final String context) {
        final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
        errorDetailBuilder.withContext(context);
        errorDetailBuilder.withException(exception);
        final ErrorDetail errorDetail = errorDetailBuilder.build();
        this.logError(errorDetail);
        throw new BadRequestException(errorDetail);
    }

    /**
     * Handles an error by creating an ErrorDetail object, logging it,
     * and throwing a BadRequestException.
     *
     * @param errorCode         the ErrorCode representing the error
     * @param userMsgExtension  additional message to be included in the user message
     * @param context           context information about where the error occurred
     * @return a RuntimeException (BadRequestException) with the error details
     */
    public final RuntimeException handleError(final ErrorCode errorCode, final String userMsgExtension, final String context) {
        final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
        errorDetailBuilder.withUserMsgFormatted(userMsgExtension);
        errorDetailBuilder.withContext(context);
        final ErrorDetail errorDetail = errorDetailBuilder.build();
        this.logError(errorDetail);
        throw new BadRequestException(errorDetail);
    }

    /**
     * Handles an error by creating an ErrorDetail object, logging it,
     * and throwing a BadRequestException.
     *
     * @param logMsgExtension   additional message to be included in the log
     * @param errorCode         the ErrorCode representing the error
     * @param context           context information about where the error occurred
     * @return a RuntimeException (BadRequestException) with the error details
     */
    public final RuntimeException handleError(final String logMsgExtension, final ErrorCode errorCode, final String context) {
        final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
        errorDetailBuilder.withLogMsgFormatted(logMsgExtension);
        errorDetailBuilder.withContext(context);
        final ErrorDetail errorDetail = errorDetailBuilder.build();
        this.logError(errorDetail);
        throw new BadRequestException(errorDetail);
    }

    /**
     * Handles an error by creating an ErrorDetail object, logging it,
     * and throwing a BadRequestException.
     *
     * @param errorCode the ErrorCode representing the error
     * @param context   context information about where the error occurred
     * @return a RuntimeException (BadRequestException) with the error details
     */
    public final RuntimeException handleError(final ErrorCode errorCode, final String context) {
        final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
        errorDetailBuilder.withContext(context);
        final ErrorDetail errorDetail = errorDetailBuilder.build();
        this.logError(errorDetail);
        throw new BadRequestException(errorDetail);
    }

    /**
     * Handles an error by creating an ErrorDetail object, logging it,
     * and throwing a BadRequestException with a user message extension.
     *
     * @param context                context information about where the error occurred
     * @param userAndLogMsgExtension additional message to be included in both user and log messages
     * @param errorCode              the ErrorCode representing the error
     * @return a RuntimeException (BadRequestException) with the error details
     */
    public final RuntimeException handleError(final String context, final String userAndLogMsgExtension, final ErrorCode errorCode) {
        final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
        errorDetailBuilder.withUserMsgFormatted(userAndLogMsgExtension);
        errorDetailBuilder.withLogMsgFormatted(userAndLogMsgExtension);
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
