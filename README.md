# CryptoService Project

This repository contains a secure cryptographic microservice (`CryptoService`) and a CLI-based client (`CryptoClient`) 
that communicate via HTTPS using TLS/mTLS. The project demonstrates secure key management, symmetric encryption using 
AES-GCM, JWT-based authorization, and OWASP-compliant Secure Coding Practices (SCPs).

---

## Project Structure

```bash
├── cryptoclient/            # CLI client for interacting with the service
├── cryptoservice/           # Secure microservice providing crypto endpoints
├── docs/                    # Diagrams, documentation, and thesis material
├── tls/                     # Scripts and certificates for TLS/mTLS
└── README.md                # Main entry point (you are here)
```

## Getting Started

To run this project locally, follow these steps:

### 1. Prerequisites
- Java 21+
- Maven 3.8+
- OpenSSL (for TLS certificate generation)

### 2. TLS/mTLS Setup

The [how-to-create-mtls-files.md](documentation/system/mtls/how-to-create-mtls-files.md) contains a list of all existing mTLS files. It also provides detailed 
instructions on how to create the necessary TLS/mTLS files using OpenSSL. It also provides detailed instructions on how 
to create the root CA.

### 3. Build and Run the Service

With the following command, you can run the service with the necessary parameters (Linux):
```bash
mvn spring-boot:run -Dspring-boot.run.arguments="--MASTER_KEYSTORE_PASSWORD=PzDXe4in3qG7LWvSgwLp0JG3Snm7UxT5kFVuG1ey3h7hyp9IVL --MASTER_KEYSTORE_PATH=src/main/resources/keystore/master-keystore.p12 --CLIENT_KEYSTORE_PASSWORD=P095NxN4cROz0IaWF8105KB6oVYNXKg2q4JqhSKf6zMawsT2Lr --CLIENT_KEYSTORE_PATH=src/main/resources/keystore/client-keystore.p12"
```

### 4. Build and Run the Clients

The tls files are already added for a client1 and a client2. You can run the clients with the following commands on (Linux):
```bash
mvn spring-boot:run -Dspring-boot.run.arguments="--client.name=client1 --client.port=8081 --client.password=changeit --client.crypto-service-url=https://localhost:8443/crypto"

mvn spring-boot:run -Dspring-boot.run.arguments="--client.name=client2 --client.port=8082 --client.password=changeit --client.crypto-service-url=https://localhost:8443/crypto"
```

### 5. Alternative: Send Requests via curl

You also can use curl to send requests to the service. The following commands show how to do this with client1 and client2.

1. **Generate a Key:**
```bash
curl -v -X POST https://localhost:8443/crypto/keys/generate \
--cert cryptoclient/src/main/resources/tls/client1.crt \
--key cryptoclient/src/main/resources/tls/client1.key \
--cacert ca/root-ca.crt
```

2. **Generate a JWT:**
```bash
curl -v -X POST https://localhost:8443/crypto/jwt/generate \
--cert cryptoclient/src/main/resources/tls/client1.crt \
--key cryptoclient/src/main/resources/tls/client1.key \
--cacert ca/root-ca.crt \
-H "Content-Type: application/json" \
-d '{"issuedTo": "ISSUED_TO_CLIENT_NAME"}'
```
Please replace `ISSUED_TO_CLIENT_NAME` with the name of the client you want to issue the JWT for (e.g. `client2`).
You will receive a JWT in the response, which you can use for encryption and decryption.

3. **Encrypt a Message:**
```bash
curl -v -X POST https://localhost:8443/crypto/encrypt \
--cert cryptoclient/src/main/resources/tls/client1.crt \
--key cryptoclient/src/main/resources/tls/client1.key \
--cacert ca/root-ca.crt \
-H "Content-Type: application/json" \
-d '{
"plainText": "MESSAGE",
"jwt": "JWT_TOKEN"
}'
```
Please replace `JWT_TOKEN` with the JWT you received in the previous step and `MESSAGE` with the message you want to encrypt.
You will receive a ciphertext in the response, which you can use for decryption.

4. **Decrypt a Message:**
```bash
curl -v -X POST https://localhost:8443/crypto/decrypt \
--cert cryptoclient/src/main/resources/tls/client2.crt \
--key cryptoclient/src/main/resources/tls/client2.key \
--cacert ca/root-ca.crt \
-H "Content-Type: application/json" \
-d '{
"cipherText": "CIPHER_TEXT",
"jwt": "JWT_TOKEN"
}'
```
Please replace `CIPHER_TEXT` with the ciphertext you received in the previous step and `JWT_TOKEN` with the JWT you received earlier.
You will receive the decrypted plaintext in the response.

## Components

### CryptoService (Spring Boot)

- Endpoints:
  - POST /crypto/keys/generate — generate symmetric key (server-side storage)
  - POST /crypto/jwt/generate — issue JWT containing keyAlias (HMAC-signed)
  - POST /crypto/encrypt — AES‑GCM encryption (Base64)
  - POST /crypto/decrypt — AES‑GCM decryption
- Security:
  - TLS/mTLS see [SecurityConfig.java](cryptoservice/src/main/java/com/projectwork/cryptoservice/boundary/security/SecurityConfig.java) and [application.properties](cryptoservice/src/main/resources/application.properties)
  - Input validation (length, charset, control chars, whitelist), see [ValidationService.java](cryptoservice/src/main/java/com/projectwork/cryptoservice/boundary/validation/ValidationService.java)
  - Authorization: JWT, keyAlias and clientName/issuedTo in [AuthService.java](cryptoservice/src/main/java/com/projectwork/cryptoservice/boundary/authorization/AuthService.java)
  - Rate limiting: see [IpRateLimitingFilter.java](cryptoservice/src/main/java/com/projectwork/cryptoservice/boundary/security/IpRateLimitingFilter.java) and [PrincipalRateLimitingFilter.java](cryptoservice/src/main/java/com/projectwork/cryptoservice/boundary/security/PrincipalRateLimitingFilter.java)
  - Safe error handling and minimal logging without secrets
- Launch Flags:
  - --MASTER_KEYSTORE_PASSWORD — password for the [master keystore](cryptoservice/src/main/resources/keystore/master-keystore.p12) (dev default: `PzDXe4in3qG7LWvSgwLp0JG3Snm7UxT5kFVuG1ey3h7hyp9IVL`)
  - --MASTER_KEYSTORE_PATH — path to the [master keystore](cryptoservice/src/main/resources/keystore/master-keystore.p12)
  - --CLIENT_KEYSTORE_PASSWORD — password for the [client keystore](cryptoservice/src/main/resources/keystore/client-keystore.p12) (dev default: `P095NxN4cROz0IaWF8105KB6oVYNXKg2q4JqhSKf6zMawsT2Lr`)
  - --CLIENT_KEYSTORE_PATH — path to the [client keystore](cryptoservice/src/main/resources/keystore/client-keystore.p12)

### CryptoClient (Spring Boot/CLI)

- Capabilities:
  - Request key generation → receive status 
  - Request JWT → share JWT with the other client 
  - Encrypt message using JWT 
  - Decrypt ciphertext using JWT
- Launch flags:
  - --client.name — logical client id (e.g. client1)
  - --client.port — local port for the client app (e.g. 8081)
  - --client.password — keystore/truststore password (dev default: changeit)
  - --client.crypto-service-url — base URL of the service (e.g. https://localhost:8443/crypto)


## Configuration

### Service Configuration

| Property                   | Description                            | Example                                         |
| -------------------------- | -------------------------------------- | ----------------------------------------------- |
| `MASTER_KEYSTORE_PATH`     | Path to master keystore                | `src/main/resources/keystore/master-keystore.p12` |
| `MASTER_KEYSTORE_PASSWORD` | Master keystore password               | `***`                                           |
| `CLIENT_KEYSTORE_PATH`     | Path to client keystore (data keys)    | `src/main/resources/keystore/client-keystore.p12` |
| `CLIENT_KEYSTORE_PASSWORD` | Client keystore password               | `***`                                           |
| `server.port`              | HTTPS port                             | `8443`                                          |
| `server.ssl.*`             | TLS config (keystore, type, key alias) | (see application config)                        |

### Client Configuration

| Property                    | Description              | Example                               |
| --------------------------- | ------------------------ | ------------------------------------- |
| `client.name`               | Client identifier / CN   | `client1`                             |
| `client.port`               | Local port               | `8081`                                |
| `client.password`           | Keystore/truststore pwd  | `changeit`                            |
| `client.crypto-service-url` | Service base URL         | `https://localhost:8443/crypto`       |
| *(TLS settings)*            | Client cert + truststore | *(see `documentation/system/mtls/*`)* |

## TLS/mTLS

- All steps: [how-to-create-mtls-files.md](documentation/system/mtls/how-to-create-mtls-files.md)
- Includes:
  - Creating Root CA (secure private key, AES‑protected)
  - Issuing server certificate for localhost 
  - Issuing client certificates (client1, client2)
  - Importing CA into truststores 
  - Verifying the chain and checking CN/SAN

## Documentation Overview

In the [`Documentation Overview`](documentation/documentation-overview.md) directory, you will find and overview of the 
documentation and direct links to all parts of the documentation.

## Project Work

The final project work and its presentation are located under [`projectwork/`](projectwork/).