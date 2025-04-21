package com.projectwork.cryptoservice.entity.encrypt;

public class EncryptResultModel {
    private String cipherText;

    public EncryptResultModel(String cipherText) { this.cipherText = cipherText; }
    
    public String getCipherText() { return cipherText; }
}
