package com.projectwork.cryptoservice.entity.models.encrypt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * EncryptRequest class that represents the request for encryption.
 * It contains the plain text and JWT required for the encryption process.
 */
@Getter
@RequiredArgsConstructor
public class EncryptResultModel {
    private final String cipherText;

}
