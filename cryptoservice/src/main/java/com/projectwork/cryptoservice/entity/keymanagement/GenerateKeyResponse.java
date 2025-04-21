package com.projectwork.cryptoservice.entity.keymanagement;

public class GenerateKeyResponse {
    private String message;

    public GenerateKeyResponse(final String message) {this.message = message;}

    public String getJwString() { return message; }
    public void setJwString(String message) { this.message = message; }
}
