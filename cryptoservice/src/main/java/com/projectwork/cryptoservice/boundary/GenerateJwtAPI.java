package com.projectwork.cryptoservice.boundary;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtResponse;

@RequestMapping("/crypto")
public interface GenerateJwtAPI {
    @RequestMapping("/jwt/generate")
    ResponseEntity<GenerateJwtResponse> generateJwtPost(@RequestBody final GenerateJwtRequest generateJwtRequest, final Principal principal);
}
