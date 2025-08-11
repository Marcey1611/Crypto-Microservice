# Documentation Overview

---

## Table of Contents

### General
- [Readme](#readme)

### CryptoService
- [Access Control Policy – CryptoService](#access-control-policy--cryptoservice)
- [API Specification – CryptoService](#api-specification--cryptoservice)
- [Key Management Policy – CryptoService](#key-management-policy--cryptoservice)
- [**Class Diagrams - CryptoService**](#complete-class-diagram--cryptoservice)
  - [Complete Class Diagram – CryptoService](#complete-class-diagram--cryptoservice)
  - [Validation Class Diagram – CryptoService](#validation-class-diagram--cryptoservice)
  - [Authorization Class Diagram – CryptoService](#authorization-class-diagram--cryptoservice)
  - [Security Class Diagram – CryptoService](#security-class-diagram--cryptoservice)
  - [Boundary Business Facade Class Diagram – CryptoService](#boundary-business-facade-class-diagram--cryptoservice)
  - [Cryptography Class Diagram – CryptoService](#cryptography-class-diagram--cryptoservice)
  - [Key Management Class Diagram – CryptoService](#key-management-class-diagram--cryptoservice)
  - [JWT Management Class Diagram – CryptoService](#jwt-management-class-diagram--cryptoservice)
  - [Error Handling Class Diagram – CryptoService](#error-handling-class-diagram--cryptoservice)
  - [Entity Class Diagram – CryptoService](#entity-class-diagram--cryptoservice)
- [Components Diagram – CryptoService](#components-diagram--cryptoservice)
- [**Sequence Diagrams – CryptoService**](#exact-sequence-diagram-decryption--cryptoservice)
  - [Exact Sequence Diagram Decryption – CryptoService](#exact-sequence-diagram-decryption--cryptoservice)
  - [Exact Sequence Diagram Encryption – CryptoService](#exact-sequence-diagram-encryption--cryptoservice)
  - [Exact Sequence Diagram Key Generation – CryptoService](#exact-sequence-diagram-key-generation--cryptoservice)
  - [Exact Sequence Diagram JWT Generation – CryptoService](#exact-sequence-diagram-jwt-generation--cryptoservice)
  - [Sequence Diagram Security Layer – CryptoService](#sequence-diagram-security-layer--cryptoservice)
  - [Simplified Sequence Diagram Decryption – CryptoService](#simplified-sequence-diagram-decryption--cryptoservice)
  - [Simplified Sequence Diagram Encryption – CryptoService](#simplified-sequence-diagram-encryption--cryptoservice)
  - [Simplified Sequence Diagram Key Generation – CryptoService](#simplified-sequence-diagram-key-generation--cryptoservice)
  - [Simplified Sequence Diagram JWT Generation – CryptoService](#simplified-sequence-diagram-jwt-generation--cryptoservice)
### System
- [How to create mTLS files for CryptoService and CryptoClient](#how-to-create-mtls-files-for-cryptoservice-and-cryptoclient)
- [System Sequence Diagram](#system-sequence-diagram)
- [System Use Case Diagram](#system-use-case-diagram)

---

### Readme
**Location in Repository:** [`README.md`](../README.md)  
**Description:** Contains, among other things, a “Getting Started” section and other relevant information about the repository and the project.

---

### Access Control Policy – CryptoService
**Location in Repository:** [`documentation/cryptoservice/access-control/access-control-policy-scp100.md`](../documentation/cryptoservice/access-control/access-control-policy-scp100.md)  
**Description:** Defines central access rules and authorization logic to secure the endpoints of the CryptoService.

### API Specification – CryptoService
**Location in Repository:** [`documentation/cryptoservice/api-spec/api-spec.yaml`](../documentation/cryptoservice/api-spec/api-spec.yaml)  
**Description:** Documents all available REST endpoints of the CryptoService, including security requirements and the expected request/response structure.

### Key Management Policy – CryptoService
**Location in Repository:** [`documentation/cryptoservice/key-management/key-management-policy-scp106.md`](../documentation/cryptoservice/key-management/key-management-policy-scp106.md)  
**Description:** Defines policies for the secure generation, storage, rotation, and deletion of cryptographic keys in the CryptoService.

### Complete Class Diagram – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/class-diagramm/complete-class-diagram.puml`](../documentation/cryptoservice/uml/class-diagramm/complete-class-diagram.puml)  
**Description:** Visualizes the class structure of the CryptoService with all interfaces, services, validation, and security components, including their relationships and methods.

### Validation Class Diagram – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/class-diagramm/validation-class-diagram.puml`](../documentation/cryptoservice/uml/class-diagramm/validation-class-diagram.puml)  
**Description:** Depicts the validation components of the CryptoService and their relationships with each other, as well as to central services such as the ValidationService.

### Authorization Class Diagram – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/class-diagramm/authorization-class-diagram.puml`](../documentation/cryptoservice/uml/class-diagramm/authorization-class-diagram.puml)  
**Description:** Shows the class structure and dependencies of the authorization components, particularly between AuthService, AuthRegistry, and their integration with central services.

### Security Class Diagram – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/class-diagramm/security-class-diagram.puml`](../documentation/cryptoservice/uml/class-diagramm/security-class-diagram.puml)  
**Description:** Illustrates the security components of the CryptoService, especially the rate-limiting filters and their configuration via the SecurityConfig.

### Boundary Business Facade Class Diagram – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/class-diagramm/boundary-business-facade-class-diagram.puml`](../documentation/cryptoservice/uml/class-diagramm/boundary-business-facade-class-diagram.puml)  
**Description:** Describes the structure and collaboration between the API interfaces, the central controller, and the business facades of the CryptoService.

### Cryptography Class Diagram – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/class-diagramm/cryptography-class-diagramm.puml`](../documentation/cryptoservice/uml/class-diagramm/cryptography-class-diagramm.puml)  
**Description:** Shows the cryptographic core components of the CryptoService for encryption and decryption using AES-GCM, as well as their internal collaboration.

### Key Management Class Diagram – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/class-diagramm/key-management-class-diagram.puml`](../documentation/cryptoservice/uml/class-diagramm/key-management-class-diagram.puml)  
**Description:** Details the key management logic of the CryptoService, including key generation, rotation, storage, and expiration control in separate components.

### JWT Management Class Diagram – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/class-diagramm/jwt-management-class-diagram.puml`](../documentation/cryptoservice/uml/class-diagramm/jwt-management-class-diagram.puml)  
**Description:** Shows the structure and dependencies of the JwtManagementService, which is responsible for creating and processing JWTs in the CryptoService.

### Error Handling Class Diagram – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/class-diagramm/error-handling-class-diagram.puml`](../documentation/cryptoservice/uml/class-diagramm/error-handling-class-diagram.puml)  
**Description:** Depicts the structured setup of the central error handling system in the CryptoService, including error classes, codes, logging, and global exception handling.

### Entity Class Diagram – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/class-diagramm/entity-class-diagram.puml`](../documentation/cryptoservice/uml/class-diagramm/entity-class-diagram.puml)  
**Description:** Presents all central data models, requests, responses, and related factory classes of the CryptoService used throughout the application lifecycle.

### Components Diagram – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/components-diagramm/components-diagramm.puml`](../documentation/cryptoservice/uml/components-diagramm/components-diagramm.puml)  
**Description:** An overview architectural diagram of the CryptoService, showing the structural composition and interaction of the main components from entry point to business logic.

### Exact Sequence Diagram Decryption – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/sequence-diagramm/exact/exact-sequence-diagram-decrypt.puml`](../documentation/cryptoservice/uml/sequence-diagramm/exact/exact-sequence-diagram-decrypt.puml)  
**Description:** Shows the complete decryption process in the CryptoService, including all involved components from request to response.

### Exact Sequence Diagram Encryption – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/sequence-diagramm/exact/exact-sequence-diagram-encrypt.puml`](../documentation/cryptoservice/uml/sequence-diagramm/exact/exact-sequence-diagram-encrypt.puml)  
**Description:** Shows the complete encryption process in the CryptoService, including all involved components from request to response.

### Exact Sequence Diagram Key Generation – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/sequence-diagramm/exact/exact-sequence-diagram-generate-key.puml`](../documentation/cryptoservice/uml/sequence-diagramm/exact/exact-sequence-diagram-generate-key.puml)  
**Description:** Shows the complete key generation process in the CryptoService, including all involved components from request to response.

### Exact Sequence Diagram JWT Generation – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/sequence-diagramm/exact/exact-sequence-diagram-generate-jwt.puml`](../documentation/cryptoservice/uml/sequence-diagramm/exact/exact-sequence-diagram-generate-jwt.puml)  
**Description:** Shows the complete JWT generation process in the CryptoService, including all involved components from request to response.

### Sequence Diagram Security Layer – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/sequence-diagramm/exact/sequence-diagram-security-layer.puml`](../documentation/cryptoservice/uml/sequence-diagramm/exact/sequence-diagram-security-layer.puml)  
**Description:** Depicts the process flow of the security layer in the CryptoService, including all involved components.

### Simplified Sequence Diagram Decryption – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/sequence-diagramm/simple/simplified-sequence-diagram-decrypt.puml`](../documentation/cryptoservice/uml/sequence-diagramm/simple/simplified-sequence-diagram-decrypt.puml)  
**Description:** Shows the simplified decryption process in the CryptoService.

### Simplified Sequence Diagram Encryption – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/sequence-diagramm/simple/simplified-sequence-diagram-encrypt.puml`](../documentation/cryptoservice/uml/sequence-diagramm/simple/simplified-sequence-diagram-encrypt.puml)  
**Description:** Shows the simplified encryption process in the CryptoService.

### Simplified Sequence Diagram Key Generation – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/sequence-diagramm/simple/simplified-sequence-diagram-generate-key.puml`](../documentation/cryptoservice/uml/sequence-diagramm/simple/simplified-sequence-diagram-generate-key.puml)  
**Description:** Shows the simplified key generation process in the CryptoService.

### Simplified Sequence Diagram JWT Generation – CryptoService
**Location in Repository:** [`documentation/cryptoservice/uml/sequence-diagramm/simple/simplified-sequence-diagram-generate-jwt.puml`](../documentation/cryptoservice/uml/sequence-diagramm/simple/simplified-sequence-diagram-generate-jwt.puml)  
**Description:** Shows the simplified JWT generation process in the CryptoService.

---

### How to create mTLS files for CryptoService and CryptoClient
**Location in Repository:** [`documentation/system/mtls/how-to-create-mtls-files.md`](../documentation/system/mtls/how-to-create-mtls-files.md)  
**Description:** Provides step-by-step instructions for creating all mTLS files for the CryptoService and the clients, including certificates, keystores, and truststores.

### System Sequence Diagram
**Location in Repository:** [`documentation/system/uml/system-sequence-diagram.puml`](../documentation/system/uml/system-sequence-diagram.puml)  
**Description:** Illustrates the full communication chain between two clients and the CryptoService for key generation, JWT creation, encryption, and decryption.

### System Use Case Diagram
**Location in Repository:** [`documentation/system/uml/system-use-case-diagramm.puml`](../documentation/system/uml/system-use-case-diagramm.puml)  
**Description:** Shows the main use cases of the CryptoService from the perspective of two clients, including the interfaces used and data flows.


