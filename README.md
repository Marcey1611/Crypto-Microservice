# 🔐 CryptoService Project

This repository contains a secure cryptographic microservice (`CryptoService`) and two CLI-based clients (`CryptoClient`) that communicate via HTTPS using TLS/mTLS. The project demonstrates secure key management, symmetric encryption using AES-GCM, JWT-based authorization, and OWASP-compliant Secure Coding Practices (SCPs).

> 📘 This project is part of a Bachelor’s thesis in Applied Computer Science, focusing on secure software design and cryptographic architecture in Java with Spring Boot.

---

## 📁 Project Structure

```bash
├── cryptoclient/            # Java CLI client for interacting with the service
├── cryptoservice/           # Secure microservice providing crypto endpoints
├── docs/                    # Diagrams, documentation, and thesis material
├── tls/                     # Scripts and certificates for TLS/mTLS
└── README.md                # Main entry point (you are here)
```

## 🚀 Getting Started

To run this project locally, follow these steps:

### 1. Prerequisites
- Java 21+
- Maven 3.8+
- OpenSSL (for TLS certificate generation)

### TLS/mTLS Setup

The [how-to-create-mtls-files.md](documentation/system/mtls/how-to-create-mtls-files.md) contains a list of all 
existing mTLS files. It also provides detailed instructions on how to create the necessary TLS/mTLS files using 
OpenSSL. It also provides detailed instructions on how to create the root CA.

### 3. Build and Run the Service

With the following command, you can run the service with the necessary environment variables:
```bash
mvn spring-boot:run -Dspring-boot.run.arguments="--MASTER_KEYSTORE_PASSWORD=PzDXe4in3qG7LWvSgwLp0JG3Snm7UxT5kFVuG1ey3h7hyp9IVL --MASTER_KEYSTORE_PATH=src/main/resources/keystore/master-keystore.p12 --CLIENT_KEYSTORE_PASSWORD=P095NxN4cROz0IaWF8105KB6oVYNXKg2q4JqhSKf6zMawsT2Lr --CLIENT_KEYSTORE_PATH=src/main/resources/keystore/client-keystore.p12"
```
The command should work on Linux and Windows.

### 4. Build and Run the Clients

The tls files are already added for a client1 and a client2. You can run the clients with the following commands:
```bash
mvn spring-boot:run -Dspring-boot.run.arguments="--client.name=client1 --client.port=8081 --client.password=changeit --client.crypto-service-url=https://localhost:8443/crypto"

mvn spring-boot:run -Dspring-boot.run.arguments="--client.name=client2 --client.port=8082 --client.password=changeit --client.crypto-service-url=https://localhost:8443/crypto"
```
