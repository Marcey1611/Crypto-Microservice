# Access Control Policy - CryptoService

## 1. Objective

This policy defines the access rules and authorization logic for the CryptoService. The goal is to allow only authorized clients to access security-critical functions (JWT generation, encryption, decryption) and to systematically prevent unauthorized access attempts.

---

## 2. Core Principles

- [77] Use only trusted system objects (e.g., server-side session objects) for making access authorization decisions
- [78] Use a single site-wide component to check access authorization
- [79] Access controls should fail securely
- [80] Deny all access if the application cannot access its security configuration information → `KeystoreInitializer.java`
- [87] Restrict access to services to only authorized users
- [88] Restrict access to application data to only authorized users
- [94] Limit the number of transactions a single user/device can perform in a given time → `RateLimitingFilter.java`
- [112] Error handling logic associated with security controls should deny access by default
- [123] Log all access control failures

---

## 3. Data Objects

| Object        | Description                                            | Source                        |
|---------------|--------------------------------------------------------|-------------------------------|
| `clientName`  | CN from mTLS certificate                               | `Principal.getName()`         |
| `keyAlias`    | Internal key alias for the client                      | `ClientKeyRegistry`           |
| `issuedTo`    | Client name from the JWT                               | `JwtManagementService`        |
| `JWT`         | JSON Web Token used for authorization validation       | Request field                 |

---

## 4. Access Control Logic

### 4.1 JWT Generation (`/generate-jwt`)

- **Rule:** `clientName` must be registered in the `ClientKeyRegistry`
- **Failure:** Access denied (`CLIENT_NOT_FOUND`) → 401 Unauthorized
- **Access Granted:** If the check passes successfully
- **Logging:** Success is logged in the `Controller`, failure is handled via the `ErrorHandler`

### 4.2 Encryption (`/encrypt`)

- **Rule 1:** `clientName` must be registered in the `ClientKeyRegistry`
- **Rule 2:** `keyAlias` in the JWT must match the registered `keyAlias` for the `clientName`
- **Rule 3:** `issuedTo` in the JWT is temporarily authorized for `keyAlias` via `AuthRegistry`
- **Failure:**
    - Rule 1: `CLIENT_NOT_FOUND` → 401 Unauthorized
    - Rule 2: `KEY_ALIAS_MISMATCH` → 403 Forbidden
- **Access Granted:** If all checks pass
- **Logging:** Success is logged in the `Controller`, failure is handled via the `ErrorHandler`

### 4.3 Decryption (`/decrypt`)

- **Rule 1:** `issuedTo` in the JWT must exactly match the `clientName`
- **Rule 2:** `keyAlias` extracted from the JWT must exist
- **Rule 3:** Access for `clientName` to `keyAlias` must be allowed in `AuthRegistry`
- **Post-Condition:** Access to `keyAlias` is revoked in `AuthRegistry` after successful use (one-time access)
- **Failure:**
    - Rule 1: `CLIENT_NAME_MISMATCH_ISSUED_TO` → 403 Forbidden
    - Rule 2: `KEY_ALIAS_NOT_FOUND` → 401 Unauthorized
    - Rule 3: `FORBIDDEN_DECRYPT_ACCESS` → 403 Forbidden
- **Access Granted:** If all checks pass
- **Logging:** Success is logged in the `Controller`, failure is handled via the `ErrorHandler`

---

## 5. Error Handling

- All security-relevant failures result in either `403 Forbidden` or `401 Unauthorized`, depending on the context
- Errors are handled with structured error codes from the `ErrorCode` class
- No fallback to less secure paths is allowed

---

## 6. Logging

- Successful authorization is logged at `DEBUG` level in the `Controller`
- All access control failures are logged via the centralized `ErrorHandler`  

