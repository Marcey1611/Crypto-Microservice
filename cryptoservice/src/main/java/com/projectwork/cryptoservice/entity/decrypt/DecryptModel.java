package com.projectwork.cryptoservice.entity.decrypt;

public class DecryptModel {
    private byte[] cipherText;
    private byte[] key;

    public DecryptModel(byte[] cipherText, byte[] key) {
        this.cipherText = cipherText;
        this.key = key;
    }
    
    public byte[] getCipherText() { return cipherText; }
    public void setCipherText(byte[] cipherText) { this.cipherText = cipherText; }
    public byte[] getKey() { return key; }
    public void setKey(byte[] key) { this.key = key; }
}
