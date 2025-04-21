package com.projectwork.cryptoservice.boundary;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.projectwork.cryptoservice.entity.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.entity.verify.VerifyRequest;

import jakarta.servlet.http.HttpServletRequest;

@RequestMapping("/crypto")
public interface GenerateKeyAPI {
    @RequestMapping("/keys/generate")
    ResponseEntity<GenerateKeyResponse> generateKeyPost(Principal principal);
}
