package com.projectwork.cryptoservice.errorhandling;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.projectwork.cryptoservice.errorhandling.exceptions.ApiException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorResponse;

/**
 * GlobalExceptionHandler is responsible for handling exceptions thrown by the application.
 * It catches ApiException and other unhandled exceptions, returning appropriate error responses.
 * SecureCodingPractices:
 * - OWASP [102] Ensuring master secrets (master-key & jwt-signing-key) are protected and initialized
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * Handles ApiException and returns a ResponseEntity with the error details.
     *
     * @param exception the ApiException to handle
     * @return ResponseEntity containing the error response
     */
    @ExceptionHandler(ApiException.class)
    public final ResponseEntity<ErrorResponse> handleApiException(final ApiException exception) {
        final ErrorDetail error = exception.getError();
        final String code = error.getCode();
        final String userMsg = error.getUserMsg();
        final HttpStatus httpStatus = exception.geHttpStatus();
        return new ResponseEntity<>(
            new ErrorResponse(code, userMsg),
                httpStatus
        );
    }

    /**
     * Handles all unhandled exceptions and returns a generic error response.
     *
     * @param exception the Exception to handle
     * @return ResponseEntity containing the error response
     */
    @ExceptionHandler(Exception.class)
    public final ResponseEntity<ErrorResponse> handleUnhandled(final Exception exception) {
        final String message = exception.getMessage();
        LOGGER.error("Unhandled exception occurred: {}", message, exception);

        final ErrorCode errorCode = ErrorCode.UNEXPECTED_ERROR;
        final ErrorDetailBuilder builder = errorCode.builder();
        final ErrorDetail error = builder.build();
        final String code = error.getCode();
        final String userMsg = error.getUserMsg();
        return new ResponseEntity<>(
                new ErrorResponse(code, userMsg),
                HttpStatus.INTERNAL_SERVER_ERROR
        );
    }
}

