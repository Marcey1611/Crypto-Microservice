package com.projectwork.cryptoservice.boundary.api;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResponse;

import jakarta.validation.Valid;

@RequestMapping("/crypto")
public interface JwtManagementAPI {
    @RequestMapping("/jwt/generate")
    ResponseEntity<GenerateJwtResponse> generateJwtPost(@Valid @RequestBody final GenerateJwtRequest generateJwtRequest, final Principal principal);
}
