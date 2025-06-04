package com.projectwork.cryptoservice.errorhandling.util;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * ErrorResponse class that represents the response for an error.
 * It contains the error code and message that will be returned to the client.
 */
@Getter
@RequiredArgsConstructor
public class ErrorResponse {
    private final String code;
    private final String message;

}
