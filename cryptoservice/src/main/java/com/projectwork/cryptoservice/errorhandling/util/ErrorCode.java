package com.projectwork.cryptoservice.errorhandling.util;

import lombok.Getter;
import org.slf4j.event.Level;

/**
 * Enum representing various error codes used in the application.
 * Each error code has a unique identifier, a user-friendly message,
 * and a log level indicating the severity of the error.
 */
@Getter
public enum ErrorCode {
    //400
    FIELD_BLANK(
        "400.001", 
        "Required field is missing.",
        Level.ERROR
    ),

    FIELD_TOO_LONG(
        "400.002", 
        "Input too long.",
        Level.ERROR
    ),
    
    INVALID_ENCODING(
        "400.003", 
        "Input has invalid format.",
        Level.ERROR
    ),
    
    ILLEGAL_CHARS(
        "400.004", 
        "Invalid characters in input.",
        Level.ERROR
    ),
    
    INVALID_JWT(
        "400.005", 
        "Invalid JWT.",
        Level.ERROR
    ),
    
    EXPIRED_JWT(
        "400.006", 
        "Invalid JWT.",
        Level.ERROR
    ),
    
    INSECURE_JWT_ALGO(
        "400.007", 
        "Invalid JWT.",
        Level.ERROR
    ),
    
    CLIENT_NOT_FOUND(
        "400.008",
        "Invalid client credentials.",
        Level.ERROR
    ),

    CLIENT_NAME_MISMATCH_ISSUED_TO(
        "400.009",
        "Invalid JWT.",
        Level.ERROR
    ),

    CLIENT_KEY_ALIAS_MISSING(
        "400.010",
        "Invalid JWT.",
        Level.ERROR
    ),

    NO_CLIENT_KEY_FOUND_FOR_ALIAS(
        "400.011",
        "Invalid JWT.",
        Level.ERROR
    ),

    CLIENT_NAME_BY_ALIAS_NOT_FOUND(
        "400.012",
        "Invalid JWT.",
        Level.ERROR
    ),

    IV_NOT_FOUND_FOR_CLIENT(
        "400.013",
        "No IV found for client.",
        Level.ERROR
    ),

    CLIENT_KEY_ALIAS_MISMATCH_CLIENT_NAME(
        "400.014",
        "Invalid JWT.",
        Level.ERROR
    ),

    UNKNOWN_CLIENT(
        "400.015",
        "Client not authorized.",
        Level.ERROR
    ),

    INVALID_ASCII(
        "400.016",
        "Invalid characters in input.",
        Level.ERROR
    ),

    INVALID_CHARSET(
        "400.017",
        "„Invalid input format.",
        Level.ERROR
    ),

    CONTAINS_CONTROL_CHAR(
        "400.018",
        "Invalid input.",
        Level.ERROR
    ),

    INVALID_BASE64(
        "400.019",
        "Invalid input.",
        Level.ERROR
    ),
    
    //500
    UNEXPECTED_ERROR(
        "500.001", 
        "Internal server error", 
        "Unexpected error", 
        Level.ERROR
    ),
    
    KEYSTORE_NOT_INITIALIZED(
        "500.002",
        "Internal server error", 
        "Keystore initializing failed.", 
        Level.ERROR
    ),

    GETTING_KEYSTORE_ENTRY_FAILED(
        "500.003",
        "Internal server error",
        "Failed to get entry from keystore.",
        Level.ERROR
    ),

    PASSWORD_DESTROY_FAILED(
        "500.004",
        "Internal server error",
        "Failed to destroy PasswordProtection.",
        Level.ERROR
    ),

    DELETING_KEYSTORE_ENTRY_FAILED(
        "500.005",
        "Internal server error", 
        "Failed to delete key entry from keystore.", 
        Level.ERROR
    ),

    AES_KEYGEN_SECURE_RANDOM_FAILED(
        "500.006",
        "Internal server error",
        "SecureRandom initialization for AES key generation failed.",
        Level.ERROR
    ),

    AES_KEYGEN_INIT_FAILED(
        "500.007",
        "Internal server error",
        "KeyGenerator initialization for AES failed.",
        Level.ERROR
    ),

    MASTER_KEY_MISSING(
        "500.008", 
        "Internal server error", 
        "Master key is missing in keystore", 
        Level.ERROR
    ),

    KEYSTORE_KEY_ACCESS_FAILED(
        "500.009",
        "Internal server error", 
        "Keystore key access failed for alias '%s'.", 
        Level.ERROR
    ),

    AES_CIPHER_INSTANCE_FAILED(
        "500.010",
        "Internal server error",
        "Failed to get AES Cipher instance.",
        Level.ERROR
    ),

    AES_CIPHER_INIT_FAILED(
        "500.011",
        "Internal server error",
        "Failed to initialize AES Cipher for key wrapping.",
        Level.ERROR
    ),

    AES_KEY_WRAP_FAILED(
        "500.012",
        "Internal server error",
        "Failed to wrap client key using AES Cipher.",
        Level.ERROR
    ),

    SETTING_KEYSTORE_ENTRY_FAILED(
        "500.013",
        "Internal server error",
        "Failed to store entry in keystore.",
        Level.ERROR
    ),

    KEYSTORE_TYPE_UNSUPPORTED(
        "500.014",
        "Internal server error",
        "Unsupported keystore type.",
        Level.ERROR
    ),

    KEYSTORE_FILE_READ_FAILED(
        "500.015",
        "Internal server error",
        "Failed to open keystore file for reading.",
        Level.ERROR
    ),

    KEYSTORE_LOADING_FAILED(
        "500.016",
        "Internal server error",
        "Failed to load keystore content.",
        Level.ERROR
    ),

    KEYSTORE_FILE_WRITE_FAILED(
        "500.017",
        "Internal server error",
        "Failed to open keystore file for writing.",
        Level.ERROR
    ),

    KEYSTORE_SAVE_FAILED(
        "500.018",
        "Internal server error",
        "Failed to store keystore data to file.",
        Level.ERROR
    ),

    CLIENT_KEY_UNWRAP_FAILED(
        "500.019",
        "Internal server error",
        "Failed to unwrap encrypted client key.",
        Level.ERROR
    ),

    JWT_SECURE_RANDOM_FAILED(
        "500.020",
        "Internal server error",
        "SecureRandom initialization for JWT key generation failed.",
        Level.ERROR
    ),

    JWT_KEYGEN_INIT_FAILED(
        "500.021",
        "Internal server error",
        "KeyGenerator initialization for JWT signing key failed.",
        Level.ERROR
    ),

    JWT_KEYGEN_INIT_PARAMS_INVALID(
        "500.022",
        "Internal server error",
        "KeyGenerator parameters for JWT signing key invalid.",
        Level.ERROR
    ),

    MASTER_KEY_SECURE_RANDOM_FAILED(
        "500.023",
        "Internal server error",
        "SecureRandom initialization for master key generation failed.",
        Level.ERROR
    ),

    MASTER_KEYGEN_INIT_FAILED(
        "500.024",
        "Internal server error",
        "KeyGenerator initialization for master key failed.",
        Level.ERROR
    ),

    MASTER_KEYGEN_PARAMS_INVALID(
        "500.025",
        "Internal server error",
        "KeyGenerator parameters for master key are invalid.",
        Level.ERROR
    ),

    INVALID_GCM_PARAMETERS(
        "500.026",
        "Internal server error",
        "Invalid GCM parameters used for decryption.",
        Level.WARN
    ),

    INVALID_CIPHERTEXT_ENCODING(
        "500.027",
        "Internal server error",
        "CipherText is not valid Base64.",
        Level.WARN
    ),

    DECRYPTION_FAILED(
        "500.028",
        "Internal server error",
        "Failed to decrypt data",
        Level.ERROR
    ),

    ENCRYPTION_FAILED(
        "500.029",
        "Internal server error",
        "Failed to encrypt data",
        Level.ERROR
    ),

    JWT_GENERATION_FAILED(
        "500.030",
        "Internal server error",
        "JWT creation failed for client %s",
        Level.ERROR
    ),

    JWT_KEYALIAS_EXTRACTION_FAILED(
        "500.031",
        "Internal server error",
        "JWT KeyAlias extraction failed",
        Level.ERROR
    ),

    JWT_ISSUEDTO_EXTRACTION_FAILED(
        "500.032",
        "Internal server error",
        "JWT KeyAlias extraction failed",
        Level.ERROR
    );


    private final String code;
    private final String userMsg;
    private final String logHeadline;
    private final Level logLevel;

    /**
     * Constructor for ErrorCode enum.
     *
     * @param code       the unique error code
     * @param userMsg    the user-friendly message associated with the error
     * @param logLevel   the logging level for this error
     */
    ErrorCode(final String code, final String userMsg, final Level logLevel) {
        this.code = code;
        this.userMsg = userMsg;
        this.logHeadline = userMsg;
        this.logLevel = logLevel;
    }

    /**
     * Constructor for ErrorCode enum with a log level and headline.
     *
     * @param code         the unique error code
     * @param userMsg      the user-friendly message associated with the error
     * @param logHeadline  the headline for logging purposes
     * @param logLevel     the logging level for this error
     */
    ErrorCode(final String code, final String userMsg, final String logHeadline, final Level logLevel) {
        this.code = code;
        this.userMsg = userMsg;
        this.logHeadline = logHeadline;
        this.logLevel = logLevel;
    }

    /**
     * Returns a builder for creating an ErrorDetail object based on this error code.
     *
     * @return an ErrorDetailBuilder instance
     */
    public ErrorDetailBuilder builder() {
        return new ErrorDetailBuilder(this);
    }
}
