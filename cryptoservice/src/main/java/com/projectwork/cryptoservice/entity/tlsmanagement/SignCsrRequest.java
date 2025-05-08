package com.projectwork.cryptoservice.entity.tlsmanagement;

public class SignCsrRequest {
    final private String csrPem;
    final private String clientName;

    public SignCsrRequest(final String csrPem, final String clientName) {
        this.csrPem = csrPem;
        this.clientName = clientName;
    }

    public String getCsrPem() {
        return csrPem;
    }

    public String getClientName() {
        return clientName;
    }
}

