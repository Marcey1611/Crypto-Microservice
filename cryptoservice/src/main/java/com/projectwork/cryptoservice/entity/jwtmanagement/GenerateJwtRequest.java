package com.projectwork.cryptoservice.entity.jwtmanagement;

public class GenerateJwtRequest {

    private final String issuedTo;

    public GenerateJwtRequest(final String issuedTo) {
        this.issuedTo = issuedTo;
    }

    public String getIssuedTo() {
        return issuedTo;
    }
}
