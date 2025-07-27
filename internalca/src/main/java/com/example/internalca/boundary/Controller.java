package com.example.internalca.boundary;

import com.example.internalca.boundary.api.CsrSignAPI;
import com.example.internalca.boundary.api.GetRootCertAPI;
import com.example.internalca.businesslogic.CaFileService;
import com.example.internalca.businesslogic.CertSignService;
import com.example.internalca.model.CsrRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class Controller implements CsrSignAPI, GetRootCertAPI {

    private final CaFileService caFileService;
    private final CertSignService signingService;

    @Override
    public ResponseEntity<Resource> getRootCertificate() {
        return ResponseEntity.ok(caFileService.loadRootCertificate());
    }

    @Override
    public ResponseEntity<String> signCsr(CsrRequest csrRequest) {
        String signedCert = signingService.signCsr(csrRequest.getCsrPem());
        return ResponseEntity.ok(signedCert);
    }
}
