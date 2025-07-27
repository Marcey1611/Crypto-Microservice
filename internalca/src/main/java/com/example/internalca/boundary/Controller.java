package com.example.internalca.boundary.controller;

import com.example.internalca.businesslogic.CaFileService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ca")
public class Controller {

    private final CaFileService caFileService;

    @GetMapping(value = "/root", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<Resource> getRootCertificate() {
        return ResponseEntity.ok(caFileService.loadRootCertificate());
    }
}
