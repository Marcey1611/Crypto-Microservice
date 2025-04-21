package com.projectwork.cryptoservice.boundary;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.jwtmanagement.GenerateJwtResponse;

import jakarta.servlet.http.HttpServletRequest;

@RequestMapping("/crypto")
public interface GenerateJwtAPI {
    @RequestMapping("/jwt/generate")
    ResponseEntity<GenerateJwtResponse> generateJwtPost(@RequestBody GenerateJwtRequest generateJwtRequest, Principal principal);
}
