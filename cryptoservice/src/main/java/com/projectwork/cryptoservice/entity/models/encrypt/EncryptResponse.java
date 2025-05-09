package com.projectwork.cryptoservice.entity.models.encrypt;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class EncryptResponse {
    private final String cipherText;
    
    public String getCipherText() { return cipherText; }
}
