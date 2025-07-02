package com.projectwork.cryptoservice.entity.models.decrypt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * DecryptRequest class that represents the request for decryption.
 * It contains the cipher text and JWT required for the decryption process.
 */
@Getter
@RequiredArgsConstructor
public class DecryptRequest {
    private final String cipherText;
    private final String jwt;
}
