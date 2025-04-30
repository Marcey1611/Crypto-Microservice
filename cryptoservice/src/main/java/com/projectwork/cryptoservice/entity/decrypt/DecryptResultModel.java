package com.projectwork.cryptoservice.entity.decrypt;

public class DecryptResultModel {
    private final String plainText;

    public DecryptResultModel(final String plainText) { this.plainText = plainText; }
    
    public String getPlainText() { return plainText; }
}
