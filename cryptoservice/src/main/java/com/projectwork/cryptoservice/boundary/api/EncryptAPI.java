package com.projectwork.cryptoservice.boundary.api;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResponse;

import jakarta.validation.Valid;

@RequestMapping("/crypto")
public interface EncryptAPI {
    @PostMapping("/encrypt")
    ResponseEntity<EncryptResponse> encryptPost(@Valid @RequestBody final EncryptRequest encryptRequest, final Principal principal);
}
