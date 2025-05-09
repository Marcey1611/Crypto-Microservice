package com.projectwork.cryptoservice.businessfacade;

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

// TODO delete after new implementation of mtls

@RequiredArgsConstructor
@Service
public class TlsManagementFacade {
    private final TlsManagementService signClientCertService;
    private final ModelsFactory modelsFactory;
    private final ResponseFactory responseFactory;

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
