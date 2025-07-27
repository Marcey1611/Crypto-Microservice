package com.example.internalca.businesslogic;

import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class CertSignService {

    @Value("${ca.root-cert-path}")
    private String rootCertPath;

    @Value("${ca.root-key-path}")
    private String rootKeyPath;

    private PrivateKey rootKey;
    private X509Certificate rootCert;

    @PostConstruct
    @SneakyThrows
    public void init() {
        this.rootKey = PemUtils.readPrivateKey(new ClassPathResource(rootKeyPath).getInputStream());
        this.rootCert = PemUtils.readX509Certificate(new ClassPathResource(rootCertPath).getInputStream());
    }

    @SneakyThrows
    public String signCsr(String csrPemString) {
        try (PEMParser parser = new PEMParser(new StringReader(csrPemString))) {
            PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parser.readObject();
            JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr).setProvider("BC");

            X500Name subject = csr.getSubject();
            PublicKey publicKey = jcaCsr.getPublicKey();

            ZonedDateTime now = ZonedDateTime.now();
            Date notBefore = Date.from(now.toInstant());
            Date notAfter = Date.from(now.plusDays(365).toInstant());

            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    rootCert,
                    serial,
                    notBefore,
                    notAfter,
                    subject,
                    publicKey
            );

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(rootKey);
            X509CertificateHolder certHolder = certBuilder.build(signer);
            X509Certificate signedCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

            StringWriter writer = new StringWriter();
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
                pemWriter.writeObject(signedCert);
            }
            return writer.toString();
        }
    }
}
