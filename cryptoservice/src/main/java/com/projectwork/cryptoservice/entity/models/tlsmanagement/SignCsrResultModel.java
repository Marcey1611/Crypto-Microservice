package com.projectwork.cryptoservice.entity.models.tlsmanagement;

// TODO delete after new implementation of mtls

public class SignCsrResultModel {
    private final String pemCert;

    public SignCsrResultModel(final String pemCert) { this.pemCert = pemCert; }
    
    public String getPemCert() { return pemCert; }
}
