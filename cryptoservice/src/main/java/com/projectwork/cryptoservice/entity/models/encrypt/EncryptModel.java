package com.projectwork.cryptoservice.entity.models.encrypt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * EncryptModel class that represents the model for encryption requests.
 * It contains the plain text, JWT, and client name.
 */
@Getter
@RequiredArgsConstructor
public class EncryptModel {
    private final String plainText;
    private final String jwt;
    private final String clientName;

}
