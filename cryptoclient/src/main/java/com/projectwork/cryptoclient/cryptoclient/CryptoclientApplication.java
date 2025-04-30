package com.projectwork.cryptoclient.cryptoclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootApplication
public class CryptoclientApplication {

	public static void main(String[] args) {
		SpringApplication.run(CryptoclientApplication.class, args);

        ObjectMapper mapper = new ObjectMapper();

        try {
            // Client 1: für Key, JWT und Encrypt
            CryptoClient client1 = new CryptoClient(
                "../cryptoservice/src/main/resources/tls/client1.p12",
                "../cryptoservice/src/main/resources/tls/truststore.jks",
                "CryptoMicroservice2025!"
            );

            // Client 2: nur für Decrypt
            CryptoClient client2 = new CryptoClient(
                "../cryptoservice/src/main/resources/tls/client2.p12",
                "../cryptoservice/src/main/resources/tls/truststore.jks",
                "CryptoMicroservice2025!"
            );

            // Key generieren
            String keyResponse = client1.generateKey();
            System.out.println("Key generated (raw): " + keyResponse);

            // JWT für Client1
            String jwtResponse = client1.generateJwt("Client2");
            JsonNode jwtNode = mapper.readTree(jwtResponse);
            String jwt = jwtNode.get("jwt").asText();

            // Encrypt mit Client1
            String encryptedResponse = client1.encrypt("How are you?", jwt);
            JsonNode encryptedNode = mapper.readTree(encryptedResponse);
            String cipherText = encryptedNode.get("cipherText").asText();
            System.out.println("Encrypted (raw): " + cipherText);

            // Decrypt mit Client2
            String decryptedResponse = client2.decrypt(cipherText, jwt);
            System.out.println("Decrypted: " + decryptedResponse);

        } catch (Exception e) {
            e.printStackTrace();
        }
		
	}

}
