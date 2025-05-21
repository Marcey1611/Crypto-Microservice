package com.projectwork.cryptoservice.errorhandling.util;

import org.slf4j.event.Level;

public enum ErrorCode {

    
    //400
    FIELD_BLANK("400.001", "Field %s must not be blank", Level.ERROR),
    FIELD_TOO_LONG("400.002", "Field %s is too long", Level.ERROR),
    INVALID_ENCODING("400.003", "Field %s has invalid encoding", Level.ERROR),
    ILLEGAL_CHARS("400.004", "Field %s contains illegal characters.", Level.ERROR),
    INVALID_JWT("400.005", "JWT ist invalid", Level.ERROR),
    EXPIRED_JWT("400.006", "JWT is expired", Level.ERROR),
    INSECURE_JWT_ALGO("400.007", "Insecure JWT algorithm", Level.ERROR),
    CLIENT_NOT_FOUND("400.008","Client %s not found",Level.WARN),
    
    //500
    UNEXPECTED_ERROR("500.001", "Internal server error", "Unexpected error", Level.ERROR),
    KEYSTORE_KEY_ACCESS_FAILED("500.002", "Internal server error", "Keystore key access failed for alias='%s': %s", Level.ERROR),
    CLIENT_KEY_DECRYPTION_FAILED("500.003", "Internal server error", "Client key decryption failed for alias='%s': %s", Level.ERROR),
    CLIENT_KEY_ENCRYPTION_FAILED("500.004", "Internal server error", "Client key encryption failed for alias='%s': %s", Level.ERROR),
    KEYSTORE_SAVE_FAILED("500.005", "Internal server error", "Failed to save keystore to path='%s': %s", Level.ERROR),
    KEYSTORE_INIT_FAILED("500.006", "Internal server error", "Failed to initialize keystore: %s", Level.ERROR),
    KEYSTORE_LOAD_FAILED("500.007", "Internal server error", "Failed to load keystore from path='%s': %s", Level.ERROR),
    MASTER_KEY_MISSING("500.008", "Internal server error", "Master key is missing in keystore", Level.ERROR),
    SETTING_KEYSTORE_ENTRY_FAILED("500.009", "Internal server error", "Failed to store entry in keystore for alias='%s': %s", Level.ERROR),
    GETTING_KEYSTORE_ENTRY_FAILED("500.010", "Internal server error", "Failed to retrieve entry from keystore for alias='%s': %s", Level.ERROR),
    DELETING_KEYSTORE_ENTRY_FAILED("500.011", "Internal server error", "Failed to delete key entry for alias='%s': %s", Level.ERROR),
    KEY_EXPIRY_CHECK_FAILED("500.012", "Internal server error", "Failed to check key expiration for alias='%s': %s", Level.ERROR),
    PASSWORD_DESTROY_FAILED("500.013", "Internal server error", "Failed to destroy PasswordProtection for alias='%s': %s", Level.ERROR),
    KEYSTORE_ALIASES_LOAD_FAILED( "500.014", "Internal server error", "Failed to load aliases from keystore: %s", Level.ERROR),

    ;

    private final String code;
    private final String userMsg;
    private final String logMsg;
    private final Level logLevel;

    ErrorCode(final String code, final String userMsg, final Level logLevel) {
        this.code = code;
        this.userMsg = userMsg;
        this.logMsg = userMsg;
        this.logLevel = logLevel;
    }

    ErrorCode(final String code, final String userMsg, final String logMsg) {
        this.code = code;
        this.userMsg = userMsg;
        this.logMsg = logMsg;
        this.logLevel = Level.ERROR;
    }

    ErrorCode(final String code, final String userMsg, final String logMsg, final Level logLevel) {
        this.code = code;
        this.userMsg = userMsg;
        this.logMsg = logMsg;
        this.logLevel = logLevel;
    }

    ErrorCode(final String code, final String userMsg) {
        this.code = code;
        this.userMsg = userMsg;
        this.logMsg = userMsg;
        this.logLevel = Level.ERROR;
    }

    public String getCode() {return code;}
    public String getUserMsg() {return userMsg;}
    public String getLogMsg() {return logMsg;}
    public Level getLogLevel() {return logLevel;}

    public ErrorDetailBuilder builder() {
        return new ErrorDetailBuilder(this);
    }
}
