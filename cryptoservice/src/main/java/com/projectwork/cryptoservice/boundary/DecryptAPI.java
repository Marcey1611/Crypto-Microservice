package com.projectwork.cryptoservice.boundary;

import com.projectwork.cryptoservice.entity.DecryptRequest;
import com.projectwork.cryptoservice.entity.DecryptResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/crypto")
public interface DecryptAPI {
    @PostMapping("/decrypt")
    ResponseEntity<DecryptResponse> decryptPost(@RequestBody DecryptRequest decryptRequest);
}
