package com.projectwork.cryptoservice.boundary.api;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResponse;

import jakarta.validation.Valid;

/**
 * DecryptAPI interface for handling decryption requests.
 * This interface defines the endpoint for decrypting data.
 */
@RequestMapping("/crypto")
public interface DecryptAPI {

    /**
     * Decrypts the provided data.
     *
     * @param decryptRequest the request containing the data to decrypt and the jwt
     * @param principal the authenticated user principal
     * @return a ResponseEntity containing the DecryptResponse with decrypted data
     */
    @PostMapping("/decrypt")
    ResponseEntity<DecryptResponse> decryptPost(@Valid @RequestBody final DecryptRequest decryptRequest, final Principal principal);
}
