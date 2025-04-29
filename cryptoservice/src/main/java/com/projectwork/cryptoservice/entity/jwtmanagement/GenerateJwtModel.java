package com.projectwork.cryptoservice.entity.jwtmanagement;

public class GenerateJwtModel {
    private final String issuedTo;
    private final String clientName;

    public GenerateJwtModel(final String issuedTo, final String clientName) {
        this.issuedTo = issuedTo;
        this.clientName = clientName;
    }

    public String getIssuedTo() {
        return issuedTo;
    }

    public String getClientName() {
        return clientName;
    }
    
}
