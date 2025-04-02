package com.projectwork.cryptoservice.entity.keymanagement;

public class GenerateKeyResultModel {
    private String message = "Client key generated.";

    public GenerateKeyResultModel() {}

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
}
