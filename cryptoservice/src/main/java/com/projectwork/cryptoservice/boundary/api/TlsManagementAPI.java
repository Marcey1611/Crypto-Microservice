package com.projectwork.cryptoservice.boundary.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.models.tlsmanagement.GetRootCaCertResponse;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrRequest;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrResponse;

// TODO delete after new implementation of mtls

@RequestMapping("/crypto")
public interface TlsManagementAPI {
    @PostMapping("/tls/sign-csr")
    ResponseEntity<SignCsrResponse> signCsrPost(@RequestBody final SignCsrRequest signCsrRequest);

    @GetMapping("/tls/root-ca")
    ResponseEntity<GetRootCaCertResponse> rootCaGet();
}
