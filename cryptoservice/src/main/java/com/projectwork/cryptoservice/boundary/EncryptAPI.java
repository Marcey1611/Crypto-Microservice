package com.projectwork.cryptoservice.boundary;

import com.projectwork.cryptoservice.entity.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/crypto")
public interface EncryptAPI {
    @PostMapping("/encrypt")
    ResponseEntity<EncryptResponse> encryptPost(@RequestBody EncryptRequest encryptRequest);
}
