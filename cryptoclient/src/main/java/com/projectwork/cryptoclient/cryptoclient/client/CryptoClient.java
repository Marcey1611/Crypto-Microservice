package com.projectwork.cryptoclient.cryptoclient.client;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Map;

@Component
public class CryptoClient {

    @Value("${client.name}")
    private String clientName;

    @Value("${client.password}")
    private String password;

    @Value("${client.crypto-service-url}")
    private String cryptoServiceUrl;

    private WebClient webClient;

    @PostConstruct
    public final void init() {
        final String keystorePath = "src/main/resources/tls/" + this.clientName + "-keystore.p12";
        final String truststorePath = "src/main/resources/tls/" + this.clientName + "-truststore.p12";

        final HttpClient httpClient;
        try {
            final KeyStore trustStore = this.loadKeyStore(truststorePath, this.password);
            final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            final KeyStore keyStore = this.loadKeyStore(keystorePath, this.password);
            final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, this.password.toCharArray());

            final SslContext sslContext = SslContextBuilder.forClient().trustManager(tmf).keyManager(kmf).build();
            httpClient = HttpClient.create().secure(spec -> spec.sslContext(sslContext));
        } catch (final IOException | GeneralSecurityException exception) {
            throw new RuntimeException("Failed to initialize SSL context", exception);
        }

        this.webClient = WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .baseUrl(this.cryptoServiceUrl)
                .build();
    }

    private KeyStore loadKeyStore(final String path, final String password) {
        try {
            final KeyStore ks = KeyStore.getInstance("PKCS12");
            try (final FileInputStream fis = new FileInputStream(path)) {
                ks.load(fis, password.toCharArray());
            }
            return ks;
        } catch (final IOException | GeneralSecurityException exception) {
            throw new RuntimeException("Failed to load keystore from " + path, exception);
        }
    }

    public final void generateKey() {
        this.webClient.post().uri("/keys/generate").retrieve().bodyToMono(String.class).block();
    }

    public final String generateJwt(final String issuedTo) {
        return this.webClient.post()
                .uri("/jwt/generate")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("issuedTo", issuedTo))
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }

    public final String encrypt(final String plainText, final String jwt) {
        return this.webClient.post()
                .uri("/encrypt")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("plainText", plainText, "jwt", jwt))
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }

    public final String decrypt(final String cipherText, final String jwt) {
        return this.webClient.post()
                .uri("/decrypt")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("cipherText", cipherText, "jwt", jwt))
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }

    public final String sendToOtherClient(final String host, final int port, final String jwt, final String cipherText) {
        final WebClient otherClient = WebClient.builder().baseUrl("http://" + host + ":" + port).build();
        return otherClient.post()
                .uri("/messages/receive")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("jwt", jwt, "cipherText", cipherText))
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }
}
