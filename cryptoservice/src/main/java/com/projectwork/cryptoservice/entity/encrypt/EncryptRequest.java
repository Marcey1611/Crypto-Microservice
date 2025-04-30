package com.projectwork.cryptoservice.entity.encrypt;

public class EncryptRequest {
    private final String plainText;
    private final String jwt;

    public EncryptRequest(final String plainText, final String jwt) {
        this.plainText = plainText;
        this.jwt = jwt;
    }
    
    public String getPlainText() { return plainText; }
    public String getJwt() { return jwt; }
}
