package com.projectwork.cryptoservice.entity.tlsmanagement;

public class GetRootCaCertResultModel {
    private final String rootCaCert;

    public GetRootCaCertResultModel(final String rootCaCert) {
        this.rootCaCert = rootCaCert;
    }

    public String getRootCaCert() {
        return rootCaCert;
    }
}
