package com.projectwork.cryptoservice.boundary;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.encrypt.EncryptResponse;

@RequestMapping("/crypto")
public interface EncryptAPI {
    @PostMapping("/encrypt")
    ResponseEntity<EncryptResponse> encryptPost(@RequestBody final EncryptRequest encryptRequest, final Principal principal);
}
