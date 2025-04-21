package com.projectwork.cryptoservice.entity.encrypt;

public class EncryptModel {
    private String plainText;
    private String jwt;
    private String clientName;

    public EncryptModel(final String plainText, final String jwt, final String clientName) {
        this.plainText = plainText;
        this.jwt = jwt;
        this.clientName = clientName;
    }
    
    public String getPlainText() { return plainText; }
    public void setPlainText(String plainText) { this.plainText = plainText; }
    public String getJwt() { return jwt; }
    public void setJwt(String jwt) { this.jwt = jwt; }
    public String getClientName() { return clientName; }
    public void setClientName(String clientName) { this.clientName = clientName;}
}
