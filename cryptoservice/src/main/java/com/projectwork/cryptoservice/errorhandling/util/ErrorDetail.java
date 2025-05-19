package com.projectwork.cryptoservice.errorhandling.util;

public class ErrorDetail {
    private final String code;
    private final String message;

    public ErrorDetail(ErrorCode errorCode, String message) {
        this.code = errorCode.getCode();
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
