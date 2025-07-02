package com.projectwork.cryptoservice.boundary.api;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResponse;

/**
 * API for managing cryptographic keys.
 * This interface defines the endpoint for generating cryptographic keys.
 */
@RequestMapping("/crypto")
public interface KeyManagementAPI {

    /**
     * Generates a cryptographic key.
     *
     * @param principal the authenticated user principal
     * @return a ResponseEntity containing the GenerateKeyResponse with result information
     */
    @RequestMapping("/keys/generate")
    ResponseEntity<GenerateKeyResponse> generateKeyPost(final Principal principal);
}
