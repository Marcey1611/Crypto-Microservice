package com.projectwork.cryptoservice.boundary.api;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResponse;

import jakarta.validation.Valid;

@RequestMapping("/crypto")
public interface DecryptAPI {
    @PostMapping("/decrypt")
    ResponseEntity<DecryptResponse> decryptPost(@Valid @RequestBody final DecryptRequest decryptRequest, final Principal principal);
}
