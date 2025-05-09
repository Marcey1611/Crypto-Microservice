package com.projectwork.cryptoservice.entity.models.encrypt;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class EncryptRequest {
    private final String plainText;
    private final String jwt;
    
    public String getPlainText() { return plainText; }
    public String getJwt() { return jwt; }
}
