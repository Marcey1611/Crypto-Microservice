package com.projectwork.cryptoservice.entity.models.jwtmanagement;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class GenerateJwtRequest {
    private final String issuedTo;

    public String getIssuedTo() {
        return issuedTo;
    }
}
