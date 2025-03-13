package com.projectwork.cryptoservice.entity;

public class DecryptResponse {
    private byte[] plainText;

    public DecryptResponse(byte[] plainText) { this.plainText = plainText; }
    
    public byte[] getPlainText() { return plainText; }
}
