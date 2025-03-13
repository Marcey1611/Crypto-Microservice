package com.projectwork.cryptoservice.entity;

public class EncryptResponse {
    private byte[] cipherText;

    public EncryptResponse(byte[] cipherText) { this.cipherText = cipherText; }
    
    public byte[] getCipherText() { return cipherText; }
}
