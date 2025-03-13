package com.projectwork.cryptoservice.entity.decrypt;

public class DecryptResultModel {
    private byte[] plainText;

    public DecryptResultModel(byte[] plainText) { this.plainText = plainText; }
    
    public byte[] getPlainText() { return plainText; }
}
