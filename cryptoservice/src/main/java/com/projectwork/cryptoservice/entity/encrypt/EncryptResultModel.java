package com.projectwork.cryptoservice.entity.encrypt;

public class EncryptResultModel {
    private final String cipherText;

    public EncryptResultModel(final String cipherText) { this.cipherText = cipherText; }
    
    public String getCipherText() { return cipherText; }
}
