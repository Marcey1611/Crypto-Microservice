package com.projectwork.cryptoservice.boundary;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResponse;

@RequestMapping("/crypto")
public interface GenerateKeyAPI {
    @RequestMapping("/keys/generate")
    ResponseEntity<GenerateKeyResponse> generateKeyPost(final Principal principal);
}
