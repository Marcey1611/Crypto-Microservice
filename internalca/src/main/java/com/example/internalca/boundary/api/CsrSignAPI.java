package com.example.internalca.boundary.api;

import com.example.internalca.model.CsrRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping("/ca")
public interface CsrSignAPI {

    @PostMapping("/sign-csr")
    ResponseEntity<String> signCsr(@RequestBody CsrRequest csrRequest);
}
