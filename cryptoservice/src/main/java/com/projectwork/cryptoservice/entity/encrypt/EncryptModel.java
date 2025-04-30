package com.projectwork.cryptoservice.entity.encrypt;

public class EncryptModel {
    private final String plainText;
    private final String jwt;
    private final String clientName;

    public EncryptModel(final String plainText, final String jwt, final String clientName) {
        this.plainText = plainText;
        this.jwt = jwt;
        this.clientName = clientName;
    }
    
    public String getPlainText() { return plainText; }
    public String getJwt() { return jwt; }
    public String getClientName() { return clientName; }
}
