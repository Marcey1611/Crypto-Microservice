package com.projectwork.cryptoservice.entity.models.jwtmanagement;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * GenerateJwtModel class that represents the request for generating a JWT.
 * It contains the issuedTo and clientName required for the JWT generation process.
 */
@Getter
@RequiredArgsConstructor
public class GenerateJwtRequest {
    private final String issuedTo;
}
