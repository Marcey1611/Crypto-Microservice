package com.projectwork.cryptoservice.errorhandling.exceptions;

import org.springframework.http.HttpStatus;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;

public class InternalServerErrorException extends ApiException {

    public InternalServerErrorException(final ErrorDetail error) {
        super(error);
    }

    @Override
    public HttpStatus geHttpStatus() {
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}
