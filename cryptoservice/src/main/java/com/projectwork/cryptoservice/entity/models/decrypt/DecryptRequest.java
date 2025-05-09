package com.projectwork.cryptoservice.entity.models.decrypt;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class DecryptRequest {
    private final String cipherText;
    private final String jwt;
    
    public String getCipherText() { return cipherText; }
    public String getJwt() { return jwt; }
}
