package com.projectwork.cryptoservice.entity.decrypt;

public class DecryptModel {
    private final String cipherText;
    private final String jwt;
    private final String clientName;

    public DecryptModel(final String cipherText, final String jwt, final String clientName) {
        this.cipherText = cipherText;
        this.jwt = jwt;
        this.clientName = clientName;
    }
    
    public String getCipherText() { return cipherText; }
    public String getJwt() { return jwt; }
    public String getClientName() { return clientName; }
}
