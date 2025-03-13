package com.projectwork.cryptoservice.entity;

public class SignResultModel {
    private byte[] signature;

    public SignResultModel(byte[] signature) { this.signature = signature; }
    
    public byte[] getSignature() { return signature; }
}
