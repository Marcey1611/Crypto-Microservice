package com.projectwork.cryptoservice.errorhandling.util;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ErrorResponse {
    private final String code;
    private final String message;

    public String getCode() {return code;}
    public String getMessage() {return message;}
}
