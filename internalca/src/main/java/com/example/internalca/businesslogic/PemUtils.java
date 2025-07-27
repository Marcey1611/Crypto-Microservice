package com.example.internalca.businesslogic;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class PemUtils {

    public static PrivateKey readPrivateKey(InputStream input) throws Exception {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(input))) {
            Object obj = pemParser.readObject();
            PEMKeyPair keyPair = (PEMKeyPair) obj;
            return new JcaPEMKeyConverter().getKeyPair(keyPair).getPrivate();
        }
    }

    public static X509Certificate readX509Certificate(InputStream input) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(input);
    }
}
