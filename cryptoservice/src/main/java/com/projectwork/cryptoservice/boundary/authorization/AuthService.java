package com.projectwork.cryptoservice.boundary.authorization;

import com.projectwork.cryptoservice.businesslogic.jwtmanagement.JwtManagementService;
import com.projectwork.cryptoservice.businesslogic.keymanagement.ClientKeyRegistry;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * AuthService class that handles authorization logic for encryption and decryption requests.
 * SCPs:
 * - [77] Use only trusted system objects (e.g. server-side session objects) for making access authorization decisions
 * - [78] Use a single site-wide component to check access authorization
 * - [79] Access controls should fail securely
 * - [80] Deny all access if the application cannot access its security configuration information
 * - [87] Restrict access to services to only authorized users
 * - [88] Restrict access to application data to only authorized users
 * - [112] Error handling logic associated with security controls should deny access by default
 * - [123] Log all access control failures
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final ClientKeyRegistry clientKeyRegistry;
    private final AuthRegistry authRegistry;
    private final JwtManagementService jwtManagementService;
    private final ErrorHandler errorHandler;

    /**
     * Authenticates a request to generate a JWT for a given client.
     *
     * @param clientName the name of the client requesting the JWT
     */
    public final void authGenerateJwtRequest(final String clientName) {
        if (!this.clientKeyRegistry.hasClient(clientName)) {
            throw this.errorHandler.handleAuthError(
                    ErrorCode.CLIENT_NOT_FOUND,
                    "While checking if client exists in the registry."
            );
        }
    }

    /**
     * Authenticates a request to encrypt data for a given client.
     *
     * @param encryptRequest the request containing the data to be encrypted
     * @param clientName the name of the client requesting encryption
     */
    public final void authEncryptRequest(final EncryptRequest encryptRequest, final String clientName) {
        final String jwt = encryptRequest.getJwt();
        final String issuedTo = this.jwtManagementService.extractIssuedTo(jwt);
        final String keyAlias = this.jwtManagementService.extractClientKeyAlias(jwt);

        if (!this.clientKeyRegistry.hasClient(clientName)) {
            throw this.errorHandler.handleAuthError(
                    ErrorCode.CLIENT_NOT_FOUND,
                    "While checking if the client exists in the registry."
            );
        }
        final String expectedAlias = this.clientKeyRegistry.getKeyAliasForClient(clientName);
        if (!keyAlias.equals(expectedAlias)) {
            throw this.errorHandler.handleForbiddenError(
                    ErrorCode.CLIENT_KEY_ALIAS_MISMATCH_CLIENT_NAME,
                    "JWT key alias does not match registered key alias for client."
            );
        }

        this.authRegistry.grantAccess(keyAlias, issuedTo);
    }

    /**
     * Authenticates a request to decrypt data.
     *
     * @param decryptRequest the request containing the data to be decrypted
     * @param clientName the name of the client requesting decryption
     */
    public final void authDecryptRequest(final DecryptRequest decryptRequest, final String clientName) {
        final String jwt = decryptRequest.getJwt();
        final String issuedTo = this.jwtManagementService.extractIssuedTo(jwt);
        final String keyAlias = this.jwtManagementService.extractClientKeyAlias(jwt);

        if (!issuedTo.equals(clientName)) {
            throw this.errorHandler.handleForbiddenError(
                    ErrorCode.CLIENT_NAME_MISMATCH_ISSUED_TO,
                    "JWT issuedTo does not match clientName."
            );
        }

        if (!this.clientKeyRegistry.hasKeyAlias(keyAlias)) {
            throw this.errorHandler.handleAuthError(
                    ErrorCode.KEY_ALIAS_NOT_FOUND,
                    "JWT key alias does not exist in the registry."
            );
        }

        if (!this.authRegistry.isAccessAllowed(keyAlias, clientName)) {
            throw this.errorHandler.handleForbiddenError(
                    ErrorCode.FORBIDDEN_DECRYPT_ACCESS,
                    "Access denied for the client to the requested keyAlias."
            );
        }

        this.authRegistry.revokeAccess(keyAlias, clientName);
    }
}
