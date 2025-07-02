package com.projectwork.cryptoservice.boundary.api;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResponse;

import jakarta.validation.Valid;

/**
 * EncryptAPI interface for handling encryption requests.
 * This interface defines the endpoint for encrypting data.
 */
@RequestMapping("/crypto")
public interface EncryptAPI {

    /**
     * Encrypts the provided data.
     *
     * @param encryptRequest the request containing the data to be encrypted and the jwt
     * @param principal the authenticated user principal
     * @return a ResponseEntity containing the EncryptResponse with the encrypted data
     */
    @PostMapping("/encrypt")
    ResponseEntity<EncryptResponse> encryptPost(@Valid @RequestBody final EncryptRequest encryptRequest, final Principal principal);
}
