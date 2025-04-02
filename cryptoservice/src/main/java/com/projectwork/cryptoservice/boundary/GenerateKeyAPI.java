package com.projectwork.cryptoservice.boundary;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResponse;

import jakarta.servlet.http.HttpServletRequest;

@RequestMapping("/crypto")
public interface GenerateKeyAPI {
    @PostMapping("/keys/generate")
    ResponseEntity<String> generateKeyPost(Principal principal);
}
