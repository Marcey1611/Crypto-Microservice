package com.projectwork.cryptoservice.errorhandling.exceptions;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;

/**
 * Abstract class representing a custom API exception.
 * It extends RuntimeException and contains an ErrorDetail object.
 * Subclasses must implement the geHttpStatus() method to return the appropriate HTTP status code.
 */
@Getter
public abstract class ApiException extends RuntimeException {
    private final ErrorDetail error;

    /**
     * Constructor for ApiException that initializes the exception with an ErrorDetail object.
     *
     * @param error the ErrorDetail object containing error information
     */
    public ApiException(final ErrorDetail error) {
        super(error.getUserMsg());
        this.error = error;
    }

    /**
     * Abstract method to get the HTTP status associated with the exception.
     *
     * @return HttpStatus representing the HTTP status for this exception
     */
    public abstract HttpStatus geHttpStatus();
}
