package com.projectwork.cryptoservice.entity.models.tlsmanagement;

// TODO delete after new implementation of mtls

public class GetRootCaCertResponse {
    private final String rootCaCert;

    public GetRootCaCertResponse(final String rootCaCert) { this.rootCaCert = rootCaCert; }

    public String getRootCaCert() { return rootCaCert; }
}
