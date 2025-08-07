package com.projectwork.cryptoclient.cryptoclient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.projectwork.cryptoclient.cryptoclient.client.CryptoClient;
import com.projectwork.cryptoclient.cryptoclient.model.IncomingMessage;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Scanner;

@SpringBootApplication
@RestController
@RequestMapping("/messages")
public class CryptoclientApplication implements CommandLineRunner {

    @Value("${otherclient.host}")
    private String otherClientHost;

    @Value("${otherclient.port}")
    private int otherClientPort;

    @Autowired
    private CryptoClient cryptoClient;

    private final ObjectMapper mapper = new ObjectMapper();

    final Scanner scanner = new Scanner(System.in);

    public static void main(final String[] args) {
        SpringApplication.run(CryptoclientApplication.class, args);
    }

    @Override
    public final void run(final String... args) {
        while (true) {
            System.out.println("Command (send, exit):");
            final String input = this.scanner.nextLine();
            switch (input) {
                case "send" -> this.handleSend();
                case "exit" -> System.exit(0);
                default -> System.out.println("Unknown command");
            }
        }
    }

    private void handleSend() {
        System.out.println("Enter message to send:");
        final String message = this.scanner.nextLine();
        System.out.println("Enter receiver:");
        final String receiverName = this.scanner.nextLine();

        this.cryptoClient.generateKey();
        final String jwtJson = this.cryptoClient.generateJwt(receiverName);
        final JsonNode jwtNode;
        try {
            jwtNode = this.mapper.readTree(jwtJson);
        } catch (final JsonProcessingException exception) {
            System.out.println("Invalid jwt");
            return;
        }
        final String jwt = jwtNode.get("jwt").asText();

        final String encryptedJson = this.cryptoClient.encrypt(message, jwt);
        final JsonNode encryptedNode;
        try {
            encryptedNode = this.mapper.readTree(encryptedJson);
        } catch (final JsonProcessingException exception) {
            System.out.println("Invalid encrypted JSON format");
            return;
        }
        final String cipherText = encryptedNode.get("cipherText").asText();

        try {
            final String response = this.cryptoClient.sendToOtherClient(this.otherClientHost, this.otherClientPort, jwt, cipherText);
            System.out.println("Response from other client: " + response);
        } catch (final Exception exception) {
            System.err.println("Error sending message to client " + receiverName);
        }

    }

    @PostMapping("/receive")
    public final ResponseEntity receiveMessage(@RequestBody final IncomingMessage message) {
        final String cipherText = message.cipherText();
        final String jwt = message.jwt();
        final String decryptedJson = this.cryptoClient.decrypt(cipherText, jwt);
        final JsonNode decryptedNode;
        try {
            decryptedNode = this.mapper.readTree(decryptedJson);
        } catch (final JsonProcessingException exception) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid JSON format in decrypted response.");
        }
        final String decrypted = decryptedNode.get("plainText").asText();
        System.out.println("Decrypted message: " + decrypted);
        System.out.println("Command (send, exit):");
        return ResponseEntity.ok("Message received.");
    }
}
