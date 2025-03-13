package com.projectwork.cryptoservice.entity.keymanagement;

public class GenerateKeyResponse {
    private String jwString;

    public GenerateKeyResponse(String jwtString) { this.jwString = jwtString; }

    public String getJwString() { return jwString; }
    public void setJwString(String jwtToken) { this.jwString = jwtToken; }
}
