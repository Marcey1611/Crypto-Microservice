package com.projectwork.cryptoservice.boundary;

import com.projectwork.cryptoservice.entity.SignRequest;
import com.projectwork.cryptoservice.entity.SignResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/crypto")
public interface SignAPI {
    @PostMapping("/sign")
    ResponseEntity<SignResponse> signPost(@RequestBody SignRequest signRequest);
}
