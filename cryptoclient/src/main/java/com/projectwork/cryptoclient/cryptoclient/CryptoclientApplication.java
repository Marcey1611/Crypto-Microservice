package com.projectwork.cryptoclient.cryptoclient;

import java.security.SecureRandom;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootApplication
public class CryptoclientApplication {
    private static final SecureRandom random = new SecureRandom();
    private static final ObjectMapper mapper = new ObjectMapper();

	public static void main(String[] args) throws JsonMappingException, JsonProcessingException {
		final ConfigurableApplicationContext context = SpringApplication.run(CryptoclientApplication.class, args);

        // Client 1: für Key, JWT und Encrypt
        CryptoClient client1 = new CryptoClient(
            null,
            "../cryptoclient/src/main/resources/tls/truststore.jks",
            "CryptoMicroservice2025!"
        );

        // Client 2: nur für Decrypt
        CryptoClient client2 = new CryptoClient(
            null,
            "../cryptoclient/src/main/resources/tls/truststore.jks",
            "CryptoMicroservice2025!"
        );

        final String message = generateFullAsciiString();

        System.out.println("");
        System.out.println("------------------------------Client 1 to Client 2------------------------------");
        testClientToClient(client1, client2, message, "anonymous-client");
        System.out.println("");
        System.out.println("------------------------------Client 2 to Client 1------------------------------");
        testClientToClient(client2, client1, message, "anonymous-client");
        System.out.println("");
        System.out.println("------------------------------Client 1 to Client 1------------------------------");
        testClientToClient(client1, client1, message, "anonymous-client");
        System.out.println("");
        System.out.println("------------------------------Client 2 to Client 2------------------------------");
        testClientToClient(client2, client2, message, "anonymous-client");
        System.out.println("");  

        final int exitCode = SpringApplication.exit(context, () -> 0);
        System.exit(exitCode);
	}

    private static void testClientToClient(final CryptoClient client1, final CryptoClient client2, final String message, final String issuedTo) throws JsonMappingException, JsonProcessingException {
        // Key generieren
        String keyResponse = client1.generateKey();
        System.out.println("Key generated (raw): " + keyResponse);

        // JWT für Client1
        String jwtResponse = client1.generateJwt(issuedTo);
        JsonNode jwtNode = mapper.readTree(jwtResponse);
        String jwt = jwtNode.get("jwt").asText();

        // Encrypt mit Client1
        String encryptedResponse = client1.encrypt(message, jwt);
        JsonNode encryptedNode = mapper.readTree(encryptedResponse);
        String cipherText = encryptedNode.get("cipherText").asText();
        System.out.println("Encrypted (raw): " + cipherText);

        // Decrypt mit Client2
        String decryptedResponse = client2.decrypt(cipherText, jwt);
        JsonNode decryptedNode = mapper.readTree(decryptedResponse);
        String plainText = decryptedNode.get("plainText").asText();
        System.out.println("Decrypted: " + plainText);

        if (message.equals(plainText)) {
            System.out.println("-------------------------------------SUCCESS------------------------------------");
        } else {
            System.out.println("-------------------------------------FAILURE------------------------------------");
            throw new RuntimeException();
        }
    }

    private static String generateFullAsciiString() {
        final int length = random.nextInt(100) + 1;
        final StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            final char c = (char) (32 + random.nextInt(95)); // 32–126
            sb.append(c);
        }
        return sb.toString();
    }
}
