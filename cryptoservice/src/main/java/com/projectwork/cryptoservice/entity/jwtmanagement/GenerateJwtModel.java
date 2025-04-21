package com.projectwork.cryptoservice.entity.jwtmanagement;

public class GenerateJwtModel {
    private String issuedTo;
    private String clientName;

    public GenerateJwtModel(final String issuedTo, final String clientName) {
        this.issuedTo = issuedTo;
        this.clientName = clientName;
    }

    public String getIssuedTo() {
        return issuedTo;
    }

    public void setIssuedTo(String issuedTo) {
        this.issuedTo = issuedTo;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }
    
}
