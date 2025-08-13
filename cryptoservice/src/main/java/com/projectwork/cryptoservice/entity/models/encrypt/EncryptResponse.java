package com.projectwork.cryptoservice.entity.models.encrypt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * EncryptModel class that represents the model for encryption requests.
 * It contains the plain text, JWT, and client name.
 */
@Getter
@RequiredArgsConstructor
public class EncryptResponse {
    private final String cipherText;
}
