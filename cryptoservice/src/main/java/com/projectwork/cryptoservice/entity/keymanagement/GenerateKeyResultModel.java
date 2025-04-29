package com.projectwork.cryptoservice.entity.keymanagement;

public class GenerateKeyResultModel {
    private String message = "Client key generated.";

    public GenerateKeyResultModel(final String message) {
        this.message = message;
    }

    public String getMessage() { return message; }
}
