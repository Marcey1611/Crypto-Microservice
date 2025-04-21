package com.projectwork.cryptoservice.entity.encrypt;

public class EncryptRequest {
    private String plainText;
    private String jwt;

    public EncryptRequest(String plainText, String jwt) {
        this.plainText = plainText;
        this.jwt = jwt;
    }
    
    public String getPlainText() { return plainText; }
    public void setPlainText(String plainText) { this.plainText = plainText; }
    public String getJwt() { return jwt; }
    public void setJwt(String jwt) { this.jwt = jwt; }
}
