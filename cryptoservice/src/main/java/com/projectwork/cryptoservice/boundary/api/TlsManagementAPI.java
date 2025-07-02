package com.projectwork.cryptoservice.boundary.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.projectwork.cryptoservice.entity.models.tlsmanagement.GetRootCaCertResponse;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrRequest;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrResponse;

/**
 * API for managing TLS (Transport Layer Security) certificates.
 * This interface defines endpoints for signing Certificate Signing Requests (CSRs)
 * and retrieving the root CA certificate.
 */
// TODO delete after new implementation of mtls
@RequestMapping("/crypto")
public interface TlsManagementAPI {

    /**
     * Signs a Certificate Signing Request (CSR).
     *
     * @param signCsrRequest the request containing the CSR to be signed
     * @return a ResponseEntity containing the SignCsrResponse with the signed certificate
     */
    @PostMapping("/tls/sign-csr")
    ResponseEntity<SignCsrResponse> signCsrPost(@RequestBody final SignCsrRequest signCsrRequest);

    /**
     * Retrieves the root CA certificate.
     *
     * @return a ResponseEntity containing the GetRootCaCertResponse with the root CA certificate
     */
    @GetMapping("/tls/root-ca")
    ResponseEntity<GetRootCaCertResponse> rootCaGet();
}
