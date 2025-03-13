package com.projectwork.cryptoservice.boundary;

import com.projectwork.cryptoservice.entity.sign.SignRequest;
import com.projectwork.cryptoservice.entity.sign.SignResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/crypto")
public interface SignAPI {
    @PostMapping("/sign")
    ResponseEntity<SignResponse> signPost(@RequestBody SignRequest signRequest);
}
