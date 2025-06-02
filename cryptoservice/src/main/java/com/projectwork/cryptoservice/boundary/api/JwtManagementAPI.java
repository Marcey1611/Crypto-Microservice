package com.projectwork.cryptoservice.boundary.api;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResponse;

import jakarta.validation.Valid;


/** * API for managing JWTs (JSON Web Tokens).
 * This interface defines the endpoint for generating JWTs.
 */
@RequestMapping("/crypto")
public interface JwtManagementAPI {

    /**
     * Generates a JWT based on the provided request.
     *
     * @param generateJwtRequest the request containing the necessary information to generate a JWT
     * @param principal the authenticated user principal
     * @return a ResponseEntity containing the GenerateJwtResponse with the generated JWT
     */
    @RequestMapping("/jwt/generate")
    ResponseEntity<GenerateJwtResponse> generateJwtPost(@Valid @RequestBody final GenerateJwtRequest generateJwtRequest, final Principal principal);
}
