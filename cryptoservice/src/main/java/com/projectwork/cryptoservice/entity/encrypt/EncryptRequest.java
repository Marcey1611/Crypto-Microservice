package com.projectwork.cryptoservice.entity.encrypt;

public class EncryptRequest {
    private byte[] plainText;
    private byte[] key;

    public EncryptRequest(byte[] plainText, byte[] key) {
        this.plainText = plainText;
        this.key = key;
    }
    
    public byte[] getPlainText() { return plainText; }
    public void setPlainText(byte[] plainText) { this.plainText = plainText; }
    public byte[] getKey() { return key; }
    public void setKey(byte[] key) { this.key = key; }
}
