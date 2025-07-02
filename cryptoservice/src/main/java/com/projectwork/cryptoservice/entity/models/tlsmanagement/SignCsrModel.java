package com.projectwork.cryptoservice.entity.models.tlsmanagement;

// TODO delete after new implementation of mtls

public class SignCsrModel {
    final private String csrPem;
    final private String clientName;

    public SignCsrModel(final String csrPem, final String clientName) {
        this.clientName = clientName;
        this.csrPem = csrPem;
    }

    public String getCsrPem() {
        return csrPem;
    }

    public String getClientName() {
        return clientName;
    }
}

