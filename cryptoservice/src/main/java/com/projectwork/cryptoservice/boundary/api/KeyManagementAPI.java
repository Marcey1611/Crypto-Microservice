package com.projectwork.cryptoservice.boundary.api;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResponse;

@RequestMapping("/crypto")
public interface KeyManagementAPI {
    @RequestMapping("/keys/generate")
    ResponseEntity<GenerateKeyResponse> generateKeyPost(final Principal principal);
}
