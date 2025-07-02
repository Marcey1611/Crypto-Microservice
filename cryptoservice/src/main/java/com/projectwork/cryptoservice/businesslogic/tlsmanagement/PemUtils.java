package com.projectwork.cryptoservice.businesslogic.tlsmanagement;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

// TODO delete after new implementation of mtls

public class PemUtils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**public static PrivateKey readPrivateKey(String pem) throws IOException {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            return new JcaPEMKeyConverter().getPrivateKey(((org.bouncycastle.openssl.PEMKeyPair) obj).getPrivateKeyInfo());
        }
    }**/

    public static PrivateKey readEncryptedPrivateKey(String pem, char[] password)
            throws Exception {

        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            PKCS8EncryptedPrivateKeyInfo encInfo = (PKCS8EncryptedPrivateKeyInfo) parser.readObject();

            InputDecryptorProvider decryptor = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                    .build(password);

            PrivateKeyInfo decryptedKeyInfo = encInfo.decryptPrivateKeyInfo(decryptor);
            return new JcaPEMKeyConverter().getPrivateKey(decryptedKeyInfo);
        } // TODO error handling
    }

    public static X509Certificate readCertificate(String pem) throws CertificateException {
        ByteArrayInputStream input = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
    }

    public static PKCS10CertificationRequest parseCsr(String pem) throws IOException {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            return (PKCS10CertificationRequest) parser.readObject();
        } // TODO error handling
    }

    public static String toPem(X509Certificate cert) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(cert);
        } // TODO error handling
        return sw.toString();
    }

    public static X509Certificate signCsrWithCa(PKCS10CertificationRequest csr, PrivateKey caKey, X509Certificate caCert)
            throws Exception {

        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60);
        Date notAfter = new Date(System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000)); // 1 Jahr gültig

        // Seriennummer zufällig
        BigInteger serial = new BigInteger(64, new SecureRandom());

        X500Name subject = csr.getSubject();
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());

        // Extrahiere PublicKey aus dem CSR
        PublicKey clientPublicKey = new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo());

        // Jetzt den Builder korrekt aufrufen:
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, clientPublicKey);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKey);

        X509CertificateHolder holder = certBuilder.build(signer);

        return new JcaX509CertificateConverter().getCertificate(holder);
    }
}
