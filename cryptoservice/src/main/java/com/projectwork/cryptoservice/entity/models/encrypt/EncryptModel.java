package com.projectwork.cryptoservice.entity.models.encrypt;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class EncryptModel {
    private final String plainText;
    private final String jwt;
    private final String clientName;
    
    public String getPlainText() { return plainText; }
    public String getJwt() { return jwt; }
    public String getClientName() { return clientName; }
}
