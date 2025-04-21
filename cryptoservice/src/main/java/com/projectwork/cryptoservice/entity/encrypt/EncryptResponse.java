package com.projectwork.cryptoservice.entity.encrypt;

public class EncryptResponse {
    private String cipherText;

    public EncryptResponse(String cipherText) { this.cipherText = cipherText; }
    
    public String getCipherText() { return cipherText; }
}
