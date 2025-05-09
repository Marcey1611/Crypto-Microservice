package com.projectwork.cryptoservice.entity.models.jwtmanagement;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class GenerateJwtResultModel {
    private final String jwt;

    public String getJwt() {
        return jwt;
    }
}
