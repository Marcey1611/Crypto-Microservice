package com.projectwork.cryptoservice.entity.decrypt;

public class DecryptResponse {
    private final String plainText;

    public DecryptResponse(final String plainText) { this.plainText = plainText; }
    
    public String getPlainText() { return plainText; }
}
