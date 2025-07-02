package com.projectwork.cryptoservice.entity.models.tlsmanagement;

// TODO delete after new implementation of mtls

public class GetRootCaCertResultModel {
    private final String rootCaCert;

    public GetRootCaCertResultModel(final String rootCaCert) {
        this.rootCaCert = rootCaCert;
    }

    public String getRootCaCert() {
        return rootCaCert;
    }
}
