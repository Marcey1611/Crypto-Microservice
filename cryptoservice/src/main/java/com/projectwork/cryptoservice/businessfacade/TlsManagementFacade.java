package com.projectwork.cryptoservice.businessfacade;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.tlsmanagement.TlsManagementService;
import com.projectwork.cryptoservice.entity.factory.ModelsFactory;
import com.projectwork.cryptoservice.entity.factory.ResponseFactory;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.GetRootCaCertResponse;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.GetRootCaCertResultModel;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrModel;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrRequest;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrResponse;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrResultModel;

import lombok.RequiredArgsConstructor;

/**
 * TlsManagementFacade class that handles the TLS certificate signing and retrieval of the root CA certificate.
 * It uses TlsManagementService to perform the signing and ModelsFactory to build the necessary models.
 */
// TODO delete after new implementation of mtls
@RequiredArgsConstructor
@Service
public class TlsManagementFacade {

    private static final Logger LOGGER = LoggerFactory.getLogger(TlsManagementFacade.class);

    private final TlsManagementService signClientCertService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    /**
     * Signs a Certificate Signing Request (CSR) and returns the signed certificate.
     *
     * @param signCsrRequest the request containing the CSR to be signed
     * @return a ResponseEntity containing the SignCsrResponse with the signed certificate
     */
    public final ResponseEntity<SignCsrResponse> signCsr(final SignCsrRequest signCsrRequest) {
        final SignCsrModel signCsrModel = this.modelsFactory.buildSignCsrModel(signCsrRequest);
        final SignCsrResultModel signCsrResultModel = this.signClientCertService.signCsr(signCsrModel);
        return this.responseFactory.buildSignCsrResponse(signCsrResultModel);
    }

    /**
     * Retrieves the root CA certificate.
     *
     * @return a ResponseEntity containing the GetRootCaCertResponse with the root CA certificate
     */
    public final ResponseEntity<GetRootCaCertResponse> getRootCaCert() {
        final GetRootCaCertResultModel getRootCaCertResultModel = this.signClientCertService.getRootCaCert();
        return this.responseFactory.buildGetRootCaCertResponse(getRootCaCertResultModel);
    }
}
