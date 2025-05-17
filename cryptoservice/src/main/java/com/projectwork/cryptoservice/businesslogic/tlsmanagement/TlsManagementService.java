package com.projectwork.cryptoservice.businesslogic.tlsmanagement;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

import com.projectwork.cryptoservice.entity.factory.ResultModelsFactory;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.GetRootCaCertResultModel;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrModel;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrResultModel;

import lombok.RequiredArgsConstructor;

// TODO delete after new implementation of mtls

@RequiredArgsConstructor
@Service
public class TlsManagementService {
    private final Path caKeyPath = Paths.get("src/main/resources/tls/rootCA.key");
    private final Path caCertPath = Paths.get("src/main/resources/tls/rootCA.crt");

    private final ResultModelsFactory resultModelsFactory;

    public SignCsrResultModel signCsr(SignCsrModel signCsrModel) {
        // 1. CA Private Key laden
        PrivateKey caKey = null;
        try {
            caKey = PemUtils.readEncryptedPrivateKey(Files.readString(caKeyPath), System.getenv("KEYSTORE_PASSWORD").toCharArray());
        } catch (final IOException exception) {
            // TODO Auto-generated catch block
            exception.printStackTrace();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        X509Certificate caCert = null;
        try {
            caCert = PemUtils.readCertificate(Files.readString(caCertPath));
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // 2. CSR parsen
        PKCS10CertificationRequest csr = null;
        try {
            csr = PemUtils.parseCsr(signCsrModel.getCsrPem());
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // 3. Client-Zertifikat generieren
        X509Certificate signedCert = null;
        try {
            signedCert = PemUtils.signCsrWithCa(csr, caKey, caCert);
        } catch (Exception e) {
            // TODO error handling
            e.printStackTrace();
        }

        // 4. Zertifikat als PEM zurückgeben
        String signedPem = null;
        try {
            signedPem = PemUtils.toPem(signedCert);
        } catch (IOException e) {
            // TODO error handling
            e.printStackTrace();
        }

        final SignCsrResultModel signCsrResultModel = resultModelsFactory.buildSignCsrResultModel(signedPem);
        return signCsrResultModel;
    }

    public GetRootCaCertResultModel getRootCaCert() {
        String pem = null;
        try {
            pem = Files.readString(caCertPath);
        } catch (IOException e) {
            // TODO error handling
            e.printStackTrace();
        }
        return resultModelsFactory.buildGetRootCaCertResultModel(pem);
    }
}
