package com.projectwork.cryptoservice.entity.keymanagement;

public class GenerateKeyModel {
    private final String clientName;

    public GenerateKeyModel(final String clientName) {
        this.clientName = clientName;
    }
    public String getClientName() {
        return clientName;
    }
}
