package com.projectwork.cryptoservice.entity.encrypt;

public class EncryptResponse {
    private final String cipherText;

    public EncryptResponse(final String cipherText) { this.cipherText = cipherText; }
    
    public String getCipherText() { return cipherText; }
}
