package com.projectwork.cryptoservice.entity.tlsmanagement;

public class SignCsrResultModel {
    private final String pemCert;

    public SignCsrResultModel(final String pemCert) { this.pemCert = pemCert; }
    
    public String getPemCert() { return pemCert; }
}
