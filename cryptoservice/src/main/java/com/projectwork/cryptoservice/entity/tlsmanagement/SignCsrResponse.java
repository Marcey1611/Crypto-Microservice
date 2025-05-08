package com.projectwork.cryptoservice.entity.tlsmanagement;

public class SignCsrResponse {
    private final String pemCert;

    public SignCsrResponse(final String pemCert) { this.pemCert = pemCert; }
    
    public String getPemSert() { return pemCert; }
}
