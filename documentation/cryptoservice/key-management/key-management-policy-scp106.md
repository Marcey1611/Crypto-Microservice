# Key Management Policy - CryptoService

## 1. Objective

This policy defines the procedures and responsibilities for the secure handling of cryptographic keys within the CryptoService. The goal is to ensure the confidentiality, integrity, and availability of keys and to establish a consistent, traceable process for managing sensitive cryptographic data in accordance with [SCP-106].

---

## 2. Types of Keys

| Key Type                  | Description                         | Storage Location              |
|---------------------------|--------------------------------------|-------------------------------|
| **Master Keys**           | Encrypt client keys                  | In Master KeyStore (secured)  |
| **Client Keys**           | Symmetric keys per client            | In Client KeyStore (secured)  |
| **JWT Initialization**    | Signature key for JWTs               | In Master KeyStore (secured)  |

---

## 3. Key Management

### 3.1. Generation of Client Keys

- All client keys are generated server-side by the `KeyManagementService`.
- Keys are generated using a cryptographically secure random number generator via `generateRandomKey()` with `SecureRandom.getInstanceStrong()`.

### 3.2. Storage of Client Keys

- Keys are stored using the `KeyStoreHelper` in a centralized P12 `ClientKeyStore`.
- Client keys are encrypted using the current master key.
- Key aliases are uniquely assigned and mapped to clients via the `ClientKeyRegistry`.

### 3.3. Access and Linking

- Access to client keys is indirect via the `ClientKeyRegistry`, which maintains a mapping `clientName → keyAlias`.
- Only registered clients are allowed to access existing keys.
- Initialization vectors (IVs) are managed separately and updated when needed.

### 3.4. Rotation

- The master key is rotated regularly using the `MasterKeyRotationTask`.
- During rotation, all stored client keys are rewrapped with the new master key.
- Old keys are securely deleted.

### 3.5. Expiry and Lifecycle

- `KeyExpirationChecker` cyclically checks the validity of keys.
- Expired aliases are removed by the `KeyCleanupTask`.
- Deletion is performed in a fail-safe and traceable manner.

---

## 4. Protection Mechanisms

- Access to the `KeyStore` is strictly limited to the designated component `KeyStoreLoader`.
- All critical operations are protected by consistent error handling via the `ErrorHandler`.
- In case of validation errors or security violations, the system fails securely (“fail secure”).

---

## 5. Auditing and Traceability

- Every key generated or deleted is identifiable via a unique alias and timestamp.
- Rotation and key management are executed only through traceable method calls.
- All key actions can logically be traced back to the initiating client.

---

## 6. Responsibility

- The `KeyManagementService` is responsible for ensuring compliance with this policy.
- Client-to-alias mapping is exclusively maintained by the `ClientKeyRegistry`.

