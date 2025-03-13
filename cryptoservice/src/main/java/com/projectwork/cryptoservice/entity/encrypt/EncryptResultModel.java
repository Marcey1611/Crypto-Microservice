package com.projectwork.cryptoservice.entity.encrypt;

public class EncryptResultModel {
    private byte[] cipherText;

    public EncryptResultModel(byte[] cipherText) { this.cipherText = cipherText; }
    
    public byte[] getCipherText() { return cipherText; }
}
