package com.projectwork.cryptoservice.entity;

public class EncryptModel {
    private byte[] plainText;
    private byte[] key;

    public EncryptModel(byte[] plainText, byte[] key) {
        this.plainText = plainText;
        this.key = key;
    }
    
    public byte[] getPlainText() { return plainText; }
    public void setPlainText(byte[] plainText) { this.plainText = plainText; }
    public byte[] getKey() { return key; }
    public void setKey(byte[] key) { this.key = key; }
}
