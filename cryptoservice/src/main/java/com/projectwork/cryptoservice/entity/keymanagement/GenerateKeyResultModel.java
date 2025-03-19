package com.projectwork.cryptoservice.entity.keymanagement;

public class GenerateKeyResultModel {
    private String jwtString;

    public GenerateKeyResultModel(String jwtToken) { this.jwtString = jwtToken; }

    public String getJwtString() { return jwtString; }
    public void setJwtString(String jwtToken) { this.jwtString = jwtToken; }
}
