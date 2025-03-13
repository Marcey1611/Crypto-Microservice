package com.projectwork.cryptoservice.entity;

public class VerifyResponse {
    private boolean verified;

    public VerifyResponse(boolean verified) { this.verified = verified; }
    
    public boolean getVerified() { return verified; }
}
