package com.projectwork.cryptoservice.errorhandling.exceptions;

import org.springframework.http.HttpStatus;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;

/**
 * Abstract class representing a custom API exception.
 * It extends RuntimeException and contains an ErrorDetail object.
 */
public class ForbiddenException extends ApiException {

    /**
     * Constructor that initializes the ForbiddenException with an ErrorDetail object.
     *
     * @param error the ErrorDetail object containing error information
     */
    public ForbiddenException(final ErrorDetail error) {
        super(error);
    }

    /**
     * Returns the HTTP status code associated with this exception.
     *
     * @return HttpStatus representing the HTTP status code
     */
    @Override
    public final HttpStatus geHttpStatus() {
        return HttpStatus.FORBIDDEN;
    }
}
