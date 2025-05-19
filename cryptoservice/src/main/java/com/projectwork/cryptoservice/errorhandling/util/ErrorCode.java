package com.projectwork.cryptoservice.errorhandling.util;

public enum ErrorCode {

    FIELD_BLANK("400.1", "Field %s must not be blank"),
    FIELD_TOO_LONG("400.2", "Field %s is too long"),
    INVALID_ENCODING("400.3", "Field %s has invalid encoding"),
    ILLEGAL_CHARS("400.4", "Field %s contains illegal characters."),
    INVALID_JWT("400.5", "JWT ist invalid"),
    EXPIRED_JWT("400.6", "JWT is expired"),
    INSECURE_JWT_ALGO("400.7", "Insecure JWT algorithm");
    

    ErrorCode(final String code, final String defaultMessage) {
        this.code = code;
        this.defaultMessage = defaultMessage;
    }

    private final String code;
    private final String defaultMessage;

    public String getCode() {
        return code;
    }

    public String getDefaultMessage() {
        return defaultMessage;
    }

    public ErrorDetail defaultMessage() {
        return new ErrorDetail(this, this.defaultMessage);
    }

    public ErrorDetail withMessage(String customMessage) {
        return new ErrorDetail(this, customMessage);
    }

    public ErrorDetail formatMessage(Object... args) {
        return new ErrorDetail(this, String.format(this.defaultMessage, args));
    }
}
