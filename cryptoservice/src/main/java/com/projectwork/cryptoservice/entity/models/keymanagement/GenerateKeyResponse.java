package com.projectwork.cryptoservice.entity.models.keymanagement;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class GenerateKeyResponse {
    private final String message;

    public String getJwString() { return message; }
}
