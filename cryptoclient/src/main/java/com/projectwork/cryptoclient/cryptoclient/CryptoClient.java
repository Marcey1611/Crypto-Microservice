package com.projectwork.cryptoclient.cryptoclient;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Map;

public class CryptoClient {

        private WebClient webClient;
    
        public CryptoClient(final String keyStorePath, final String trustStorePath, final String password) {
                try {
                    // TrustStore laden
                    final KeyStore trustStore = loadKeyStore(trustStorePath, password);
                    final TrustManagerFactory tmf = initTrustManagerFactory(trustStore);
            
                    // Wenn KeyStore vorhanden → laden (für später mTLS)
                    KeyManagerFactory kmf = null;
                    if (keyStorePath != null) {
                        final KeyStore keyStore = loadKeyStore(keyStorePath, password);
                        kmf = initKeyManagerFactory(keyStore, password);
                    }
            
                    // SSL-Kontext erstellen
                    final SslContextBuilder sslBuilder = SslContextBuilder.forClient().trustManager(tmf);
                    if (kmf != null) {
                        sslBuilder.keyManager(kmf);
                    }
            
                    final SslContext sslContext = sslBuilder.build();
                    final HttpClient httpClient = HttpClient.create()
                            .secure(spec -> spec.sslContext(sslContext));
            
                    this.webClient = WebClient.builder()
                            .clientConnector(new ReactorClientHttpConnector(httpClient))
                            .baseUrl("https://localhost:8443/crypto")
                            .build();
            
                } catch (final GeneralSecurityException | IOException exception) {
                    throw new IllegalStateException("Failed to initialize CryptoClient", exception);
                }
            }
            
            

        private KeyStore loadKeyStore(final String path, final String password) throws GeneralSecurityException, IOException {
                final KeyStore ks = KeyStore.getInstance("PKCS12");
                try (final FileInputStream fis = new FileInputStream(path)) {
                        ks.load(fis, password.toCharArray());
                }
                return ks;
        }

        private KeyManagerFactory initKeyManagerFactory(final KeyStore ks, final String password) throws GeneralSecurityException {
                final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(ks, password.toCharArray());
                return kmf;
        }

        private TrustManagerFactory initTrustManagerFactory(final KeyStore ts) throws GeneralSecurityException {
                final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(ts);
                return tmf;
        }
    
        public String generateKey() {
            return webClient.post()
                    .uri("/keys/generate")
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();
        }
    
        public String generateJwt(final String issuedTo) {
            return webClient.post()
                    .uri("/jwt/generate")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("issuedTo", issuedTo))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();
        }
    
        public String encrypt(final String plainText, final String jwt) {
            return webClient.post()
                    .uri("/encrypt")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("plainText", plainText, "jwt", jwt))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();
        }
    
        public String decrypt(final String cipherText, final String jwt) {
            return webClient.post()
                    .uri("/decrypt")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("cipherText", cipherText, "jwt", jwt))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();
        }
}
    