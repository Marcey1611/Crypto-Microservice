package com.projectwork.cryptoservice.boundary.validation;

import lombok.Getter;

/**
 * Enum representing the names of fields used in encryption and JWT management.
 * This enum is used for validation and error handling purposes.
 */
@Getter
public enum FieldName {

    CIPHER_TEXT("cipherText"),
    JWT("jwt"),
    PLAIN_TEXT("plainText"),
    ISSUED_TO("issuedTo"),
    ALGORITHM_HEADER("algorithm (header)"),
    KEY_ALIAS("keyAlias");

    private final String value;

    FieldName(final String value) {
        this.value = value;
    }
}

