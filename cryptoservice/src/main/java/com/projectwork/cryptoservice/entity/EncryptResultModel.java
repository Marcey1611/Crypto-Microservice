package com.projectwork.cryptoservice.entity;

public class EncryptResultModel {
    private byte[] cipherText;

    public EncryptResultModel(byte[] cipherText) { this.cipherText = cipherText; }
    
    public byte[] getCipherText() { return cipherText; }
}
