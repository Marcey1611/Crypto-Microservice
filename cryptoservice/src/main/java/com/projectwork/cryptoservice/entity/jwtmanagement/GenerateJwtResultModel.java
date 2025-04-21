package com.projectwork.cryptoservice.entity.jwtmanagement;

public class GenerateJwtResultModel {
    private String jwt;

    public GenerateJwtResultModel(String jwt) {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
    }
}
