package com.projectwork.cryptoservice.entity.tlsmanagement;

public class GetRootCaCertResponse {
    private final String rootCaCert;

    public GetRootCaCertResponse(final String rootCaCert) { this.rootCaCert = rootCaCert; }

    public String getRootCaCert() { return rootCaCert; }
}
