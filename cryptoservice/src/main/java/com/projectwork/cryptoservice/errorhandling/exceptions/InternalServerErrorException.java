package com.projectwork.cryptoservice.errorhandling.exceptions;

import org.springframework.http.HttpStatus;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;

/**
 * Abstract class representing a custom API exception.
 * It extends RuntimeException and contains an ErrorDetail object.
 * Subclasses must implement the geHttpStatus() method to return the appropriate HTTP status code.
 */
public class InternalServerErrorException extends ApiException {

    /**
     * Constructor that initializes the InternalServerErrorException with an ErrorDetail object.
     *
     * @param error the ErrorDetail object containing error information
     */
    public InternalServerErrorException(final ErrorDetail error) {
        super(error);
    }

    /**
     * Returns the HTTP status code associated with this exception.
     * In this case, it returns HttpStatus.INTERNAL_SERVER_ERROR.
     *
     * @return HttpStatus representing the HTTP status code
     */
    @Override
    public final HttpStatus geHttpStatus() {
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}
