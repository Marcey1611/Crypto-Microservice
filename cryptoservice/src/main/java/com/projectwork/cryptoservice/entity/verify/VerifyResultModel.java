package com.projectwork.cryptoservice.entity.verify;

public class VerifyResultModel {
    private boolean verified;

    public VerifyResultModel(boolean verified) { this.verified = verified; }
    
    public boolean getVerified() { return verified; }
}
