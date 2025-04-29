package com.projectwork.cryptoservice.boundary;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.decrypt.DecryptResponse;

@RequestMapping("/crypto")
public interface DecryptAPI {
    @PostMapping("/decrypt")
    ResponseEntity<DecryptResponse> decryptPost(@RequestBody final DecryptRequest decryptRequest, final Principal principal);
}
