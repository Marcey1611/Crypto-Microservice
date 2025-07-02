package com.projectwork.cryptoservice.entity.models.decrypt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * DecryptModel class that represents the model for decryption requests.
 * It contains the cipher text, JWT, and client name.
 */
@Getter
@RequiredArgsConstructor
public class DecryptResponse {
    private final String plainText;
}
