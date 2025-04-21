package com.projectwork.cryptoservice.entity.jwtmanagement;

public class GenerateJwtResponse {
    private String jwt;

    public GenerateJwtResponse(String jwt) {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
    }
}
