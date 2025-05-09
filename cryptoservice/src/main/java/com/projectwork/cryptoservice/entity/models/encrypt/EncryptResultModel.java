package com.projectwork.cryptoservice.entity.models.encrypt;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class EncryptResultModel {
    private final String cipherText;
    
    public String getCipherText() { return cipherText; }
}
