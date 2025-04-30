package com.projectwork.cryptoservice.entity.jwtmanagement;

public class GenerateJwtResultModel {
    private final String jwt;

    public GenerateJwtResultModel(final String jwt) {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }
}
