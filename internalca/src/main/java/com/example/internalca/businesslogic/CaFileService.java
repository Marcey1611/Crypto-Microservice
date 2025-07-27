package com.example.internalca.businesslogic;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CaFileService {

    @Value("${ca.root-cert-path}")
    private String rootCertPath;

    public Resource loadRootCertificate() {
        return new ClassPathResource(rootCertPath.replace("classpath:", ""));
    }
}
