package com.projectwork.cryptoservice.boundary;

import com.projectwork.cryptoservice.entity.verify.VerifyRequest;
import com.projectwork.cryptoservice.entity.verify.VerifyResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/crypto")
public interface VerifyAPI {
    @PostMapping("/verify")
    ResponseEntity<VerifyResponse> verifyPost(@RequestBody VerifyRequest verifyRequest);
}
