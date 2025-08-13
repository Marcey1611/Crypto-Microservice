package com.projectwork.cryptoservice.entity.models.keymanagement;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * GenerateKeyResponse class that represents the response for generating a key.
 * It contains the message that indicates the result of the key generation process.
 */
@Getter
@RequiredArgsConstructor
public class GenerateKeyResponse {
    private final String message;
}
