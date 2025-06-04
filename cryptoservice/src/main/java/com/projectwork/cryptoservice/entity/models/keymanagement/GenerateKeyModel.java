package com.projectwork.cryptoservice.entity.models.keymanagement;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * GenerateKeyModel class that represents the request for generating a key.
 * It contains the clientName required for the key generation process.
 */
@Getter
@RequiredArgsConstructor
public class GenerateKeyModel {
    private final String clientName;
}
