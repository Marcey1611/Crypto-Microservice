package com.projectwork.cryptoservice.entity.decrypt;

public class DecryptRequest {
    private final String cipherText;
    private final String jwt;

    public DecryptRequest(final String cipherText, final String jwt) {
        this.cipherText = cipherText;
        this.jwt = jwt;
    }
    
    public String getCipherText() { return cipherText; }
    public String getJwt() { return jwt; }
}
