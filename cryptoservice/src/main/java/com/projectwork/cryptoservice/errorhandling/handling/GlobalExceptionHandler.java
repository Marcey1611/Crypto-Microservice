package com.projectwork.cryptoservice.errorhandling.handling;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.projectwork.cryptoservice.errorhandling.exceptions.ApiException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorResponse;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorResponse> handleApiException(final ApiException exception) {
        final ErrorDetail error = exception.getError();
        return new ResponseEntity<>(
            new ErrorResponse(error.getCode(), error.getUserMsg()),
            exception.geHttpStatus()
        );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnhandled(final Exception exception) {
        final ErrorDetail error = ErrorCode.UNEXPECTED_ERROR.builder().build();
        return new ResponseEntity<>(
            new ErrorResponse(error.getCode(), error.getUserMsg()),
            HttpStatus.INTERNAL_SERVER_ERROR
        );
    }
}

