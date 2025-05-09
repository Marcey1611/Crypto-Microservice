package com.projectwork.cryptoservice.entity.models.keymanagement;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class GenerateKeyModel {
    private final String clientName;

    public String getClientName() {
        return clientName;
    }
}
