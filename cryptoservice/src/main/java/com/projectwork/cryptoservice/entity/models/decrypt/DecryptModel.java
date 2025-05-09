package com.projectwork.cryptoservice.entity.models.decrypt;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class DecryptModel {
    private final String cipherText;
    private final String jwt;
    private final String clientName;
    
    public String getCipherText() { return cipherText; }
    public String getJwt() { return jwt; }
    public String getClientName() { return clientName; }
}
