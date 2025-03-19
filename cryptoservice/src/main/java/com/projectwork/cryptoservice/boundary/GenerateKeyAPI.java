package com.projectwork.cryptoservice.boundary;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResponse;

@RequestMapping("/crypto")
public interface GenerateKeyAPI {
    @PostMapping("/keys/generate")
    ResponseEntity<GenerateKeyResponse> generateKeyPost();
}
