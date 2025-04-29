package com.projectwork.cryptoclient.cryptoclient;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import reactor.netty.tcp.TcpClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Map;

public class CryptoClient {

    private final WebClient webClient;

    public CryptoClient() throws Exception {
        // Deine Zertifikate laden
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("../cryptoservice/src/main/resources/tls/client1.p12"), "CryptoMicroservice2025!".toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "CryptoMicroservice2025!".toCharArray());

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(new FileInputStream("../cryptoservice/src/main/resources//tls/truststore.jks"), "CryptoMicroservice2025!".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        // 👉 SslContext über Netty bauen
        SslContext sslContext = SslContextBuilder.forClient()
                .keyManager(kmf)
                .trustManager(tmf)
                .build();

        // HttpClient mit Netty-SSL-Context
        HttpClient httpClient = HttpClient.create()
                .secure(spec -> spec.sslContext(sslContext));

        this.webClient = WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .baseUrl("https://localhost:8443/crypto")
                .build();
    }

    public String generateKey() {
        return webClient.post()
                .uri("/keys/generate")
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }

    public String generateJwt(String issuedTo) {
        return webClient.post()
                .uri("/jwt/generate")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"issuedTo\":\"" + issuedTo + "\"}")
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }

    public String encrypt(String plainText, String jwt) {
        return webClient.post()
                .uri("/encrypt")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("plainText", plainText, "jwt", jwt))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        }

        public String decrypt(String cipherText, String jwt) {
        return webClient.post()
                .uri("/decrypt")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("cipherText", cipherText, "jwt", jwt))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        }

}
