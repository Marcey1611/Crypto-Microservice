package com.projectwork.cryptoservice.entity.sign;

public class SignResponse {
    private byte[] signature;

    public SignResponse(byte[] signature) { this.signature = signature; }
    
    public byte[] getSignature() { return signature; }
}
