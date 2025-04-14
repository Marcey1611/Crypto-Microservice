package com.projectwork.cryptoservice.boundary;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

@RequestMapping("/crypto")
public interface GenerateJwtAPI {
    @RequestMapping("/jwt/generate")
    ResponseEntity<String> generateJwtPost(HttpServletRequest request, Principal principal);
}
