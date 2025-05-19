package com.projectwork.cryptoservice.errorhandling.exceptions;

import org.springframework.http.HttpStatus;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;

public class BadRequestException extends ApiException {

    public BadRequestException(final ErrorDetail error) {
        super(error);
    }

    @Override
    public HttpStatus geHttpStatus() {
        return HttpStatus.BAD_REQUEST;
    }
}
