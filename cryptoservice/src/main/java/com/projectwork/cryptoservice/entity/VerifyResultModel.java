package com.projectwork.cryptoservice.entity;

public class VerifyResultModel {
    private boolean verified;

    public VerifyResultModel(boolean verified) { this.verified = verified; }
    
    public boolean getVerified() { return verified; }
}
