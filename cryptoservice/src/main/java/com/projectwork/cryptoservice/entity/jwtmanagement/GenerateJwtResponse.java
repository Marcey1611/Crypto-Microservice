package com.projectwork.cryptoservice.entity.jwtmanagement;

public class GenerateJwtResponse {
    private final String jwt;

    public GenerateJwtResponse(final String jwt) {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }

}
