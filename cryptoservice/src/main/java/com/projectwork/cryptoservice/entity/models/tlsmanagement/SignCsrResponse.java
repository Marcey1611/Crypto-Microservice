package com.projectwork.cryptoservice.entity.models.tlsmanagement;

// TODO delete after new implementation of mtls

public class SignCsrResponse {
    private final String pemCert;

    public SignCsrResponse(final String pemCert) { this.pemCert = pemCert; }
    
    public String getPemSert() { return pemCert; }
}
