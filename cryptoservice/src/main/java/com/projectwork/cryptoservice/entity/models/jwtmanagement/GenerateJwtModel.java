package com.projectwork.cryptoservice.entity.models.jwtmanagement;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class GenerateJwtModel {
    private final String issuedTo;
    private final String clientName;

    public String getIssuedTo() {
        return issuedTo;
    }

    public String getClientName() {
        return clientName;
    }
    
}
