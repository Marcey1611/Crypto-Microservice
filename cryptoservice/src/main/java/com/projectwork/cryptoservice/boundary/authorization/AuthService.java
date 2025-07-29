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
 *
 * SCPs:
 * - [77] Use only trusted system objects (e.g. server-side session objects) for making access authorization decisions
 * - [87] Restrict access to services to only authorized users
 * - [88] Restrict access to application data to only authorized users
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
    public void authGenerateJwtRequest(final String clientName) {
        if (!clientKeyRegistry.hasClient(clientName)) {
            final String context = String.format("While checking if client '%s' exists in the registry.", clientName);
            throw this.errorHandler.handleError(
                    ErrorCode.CLIENT_NOT_FOUND,
                    context
            );
        }
    }

    /**
     * Authenticates a request to encrypt data for a given client.
     *
     * @param encryptRequest the request containing the data to be encrypted
     * @param clientName the name of the client requesting encryption
     */
    public void authEncryptRequest(final EncryptRequest encryptRequest, final String clientName) {
        final String jwt = encryptRequest.getJwt();
        final String issuedTo = jwtManagementService.extractIssuedTo(jwt);
        final String keyAlias = clientKeyRegistry.getKeyAliasForClient(clientName);

        if (!clientKeyRegistry.hasClient(clientName)) {
            final String context = String.format("While checking if client '%s' exists in the registry.", clientName);
            throw this.errorHandler.handleError(
                    ErrorCode.CLIENT_NOT_FOUND,
                    context
            );
        }
        final String expectedAlias = clientKeyRegistry.getKeyAliasForClient(clientName);
        if (!keyAlias.equals(expectedAlias)) {
            final String context = String.format(
                    "JWT key alias '%s' does not match registered key alias for client '%s'.",
                    keyAlias,
                    clientName
            );
            throw this.errorHandler.handleError(
                    ErrorCode.CLIENT_KEY_ALIAS_MISMATCH_CLIENT_NAME,
                    context
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
    public void authDecryptRequest(final DecryptRequest decryptRequest, final String clientName) {
        final String jwt = decryptRequest.getJwt();
        final String issuedTo = jwtManagementService.extractIssuedTo(jwt);
        final String keyAlias = jwtManagementService.extractClientKeyAlias(jwt);

        if (!issuedTo.equals(clientName)) {
            final String context = String.format("JWT issuedTo='%s' does not match clientName='%s'", issuedTo, clientName);
            throw this.errorHandler.handleError(
                    ErrorCode.CLIENT_NAME_MISMATCH_ISSUED_TO,
                    context
            );
        }

        if (!clientKeyRegistry.hasKeyAlias(keyAlias)) {
            final String context = String.format("JWT key alias '%s' does not exist in the registry.", keyAlias);
            throw this.errorHandler.handleError(
                    ErrorCode.KEY_ALIAS_NOT_FOUND,
                    context
            );
        }

        if (!authRegistry.isAccessAllowed(keyAlias, clientName)) {
            final String context = String.format("Access denied for client '%s' with key alias '%s'.", clientName, keyAlias);
            throw this.errorHandler.handleError(
                    ErrorCode.UNAUTHORIZED_DECRYPT_ACCESS,
                    context
            );
        }

        this.authRegistry.revokeAccess(keyAlias, clientName);
    }
}
