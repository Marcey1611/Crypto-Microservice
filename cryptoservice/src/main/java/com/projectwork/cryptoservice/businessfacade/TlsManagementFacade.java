package com.projectwork.cryptoservice.businessfacade;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.businesslogic.tlsmanagement.TlsManagementService;
import com.projectwork.cryptoservice.entity.tlsmanagement.GetRootCaCertResponse;
import com.projectwork.cryptoservice.entity.tlsmanagement.GetRootCaCertResultModel;
import com.projectwork.cryptoservice.entity.tlsmanagement.SignCsrModel;
import com.projectwork.cryptoservice.entity.tlsmanagement.SignCsrRequest;
import com.projectwork.cryptoservice.entity.tlsmanagement.SignCsrResponse;
import com.projectwork.cryptoservice.entity.tlsmanagement.SignCsrResultModel;
import com.projectwork.cryptoservice.factory.ModelsFactory;
import com.projectwork.cryptoservice.factory.ResponseFactory;

@Service
public class TlsManagementFacade {

    private final TlsManagementService signClientCertService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

    public TlsManagementFacade(final TlsManagementService signClientCertService, final ModelsFactory modelsFactory, final ResponseFactory responseFactory) {
        this.responseFactory = responseFactory;
        this.modelsFactory = modelsFactory;
        this.signClientCertService = signClientCertService;
    }

    public ResponseEntity<SignCsrResponse> signCsr(final SignCsrRequest signCsrRequest) {
        final SignCsrModel signCsrModel = modelsFactory.buildSignCsrModel(signCsrRequest);
        final SignCsrResultModel signCsrResultModel = signClientCertService.signCsr(signCsrModel);
        return responseFactory.buildSignCsrResponse(signCsrResultModel);
    }

    public ResponseEntity<GetRootCaCertResponse> getRootCaCert() {
        final GetRootCaCertResultModel getRootCaCertResultModel = signClientCertService.getRootCaCert();
        return responseFactory.buildGetRootCaCertResponse(getRootCaCertResultModel);
    }
}
