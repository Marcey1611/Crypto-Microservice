package com.projectwork.cryptoservice.errorhandling.exceptions;

import org.springframework.http.HttpStatus;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;

public abstract class ApiException extends RuntimeException {
    private final ErrorDetail error;

    public ApiException(final ErrorDetail error) {
        super(error.getMessage());
        this.error = error;
    }

    public ErrorDetail getError() {
        return error;
    }

    public abstract HttpStatus geHttpStatus();
}
