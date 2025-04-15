package com.projectwork.cryptoservice.entity.jwtmanagement;

public class GenerateJwtRequest {
    private String issuedTo;

    public GenerateJwtRequest(String issuedTo) {
        this.issuedTo = issuedTo;
    }

    public String getIssuedTo() {
        return issuedTo;
    }
    
    public void setIssuedTo(String issuedTo) {
        this.issuedTo = issuedTo;
    }
}
