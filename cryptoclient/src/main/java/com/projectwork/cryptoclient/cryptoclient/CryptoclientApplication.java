package com.projectwork.cryptoclient.cryptoclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootApplication
public class CryptoclientApplication {

	public static void main(String[] args) {
		SpringApplication.run(CryptoclientApplication.class, args);

		CryptoClient client;
        try {
            client = new CryptoClient();
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }

        ObjectMapper mapper = new ObjectMapper();

        try {
            // 1. Key generieren (auch wenn schon vorhanden)
            String keyResponse = client.generateKey();
            System.out.println("Key generated (raw): " + keyResponse);

            // 2. JWT anfordern
            String jwtResponse = client.generateJwt("Client1");
            System.out.println("JWT generated (raw): " + jwtResponse);

            // JWT aus der JSON-Antwort extrahieren
            JsonNode jwtNode = mapper.readTree(jwtResponse);
            String jwt = jwtNode.get("jwt").asText();

            // 3. Verschlüsseln
            String encryptedResponse = client.encrypt("How are you?", jwt);
            System.out.println("Encrypted (raw): " + encryptedResponse);

            // Ciphertext extrahieren (optional, je nach Response-Struktur)
            JsonNode encryptedNode = mapper.readTree(encryptedResponse);
            String cipherText = encryptedNode.get("cipherText").asText();

            // 4. Entschlüsseln
            String decryptedResponse = client.decrypt(cipherText, jwt);
            System.out.println("Decrypted: " + decryptedResponse);

        } catch (Exception e) {
            e.printStackTrace();
        }
		
	}

}
