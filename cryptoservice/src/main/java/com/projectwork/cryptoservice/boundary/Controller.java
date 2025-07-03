package com.projectwork.cryptoservice.boundary;

import java.security.Principal;

import com.projectwork.cryptoservice.boundary.validation.DecryptValidator;
import com.projectwork.cryptoservice.boundary.validation.EncryptValidator;
import com.projectwork.cryptoservice.boundary.validation.JwtManagementValidator;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import com.projectwork.cryptoservice.logging.CustomLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import com.projectwork.cryptoservice.boundary.api.DecryptAPI;
import com.projectwork.cryptoservice.boundary.api.EncryptAPI;
import com.projectwork.cryptoservice.boundary.api.JwtManagementAPI;
import com.projectwork.cryptoservice.boundary.api.KeyManagementAPI;
import com.projectwork.cryptoservice.boundary.api.TlsManagementAPI;
import com.projectwork.cryptoservice.businessfacade.DecryptFacade;
import com.projectwork.cryptoservice.businessfacade.EncryptFacade;
import com.projectwork.cryptoservice.businessfacade.JwtManagementFacade;
import com.projectwork.cryptoservice.businessfacade.KeyManagementFacade;
import com.projectwork.cryptoservice.businessfacade.TlsManagementFacade;
import com.projectwork.cryptoservice.businesslogic.keymanagement.ClientKeyRegistry;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResponse;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResponse;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResponse;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResponse;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.GetRootCaCertResponse;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrRequest;
import com.projectwork.cryptoservice.entity.models.tlsmanagement.SignCsrResponse;
import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

import lombok.RequiredArgsConstructor;

/** * Controller class that handles incoming requests for encryption, decryption,
 * key management, JWT management, and TLS management.
 * It uses various facades to process the requests and returns appropriate responses.
 */
@RequiredArgsConstructor
@RestController
public class Controller implements EncryptAPI, DecryptAPI, KeyManagementAPI, JwtManagementAPI, TlsManagementAPI {

    private static final Logger logger = LoggerFactory.getLogger(Controller.class);
    private final CustomLogger customLogger;

    private final EncryptFacade encryptFacade;
    private final DecryptFacade decryptFacade;
    private final KeyManagementFacade keyManagementFacade;
    private final JwtManagementFacade jwtManagementFacade;
    private final TlsManagementFacade tlsManagementFacade;
    private final EncryptValidator encryptValidator;
    private final JwtManagementValidator jwtManagementValidator;
    private final DecryptValidator decryptValidator;
    private final ClientKeyRegistry clientKeyRegistry;

    /**
     * Handles encryption requests.
     *
     * @param encryptRequest the request containing the data to be encrypted
     * @param principal      the authenticated user principal
     * @return a response entity containing the encryption result
     */
    @Override
    public final ResponseEntity<EncryptResponse> encryptPost(final EncryptRequest encryptRequest, final Principal principal) {
        final String clientName = this.resolveClientName(principal);
        logger.info("Received encrypt request for client '{}'", clientName);
        this.checkClientNameExists(clientName);

        this.encryptValidator.validateEncryptRequest(encryptRequest);
        logger.debug("Encrypt request validated for client '{}'", clientName);

        final ResponseEntity<EncryptResponse> response = this.encryptFacade.processEncryption(encryptRequest, clientName);
        logger.info("Encryption successful for client '{}'", clientName);
        return response;
    }

    /**
     * Handles decryption requests.
     *
     * @param decryptRequest the request containing the data to be decrypted
     * @param principal      the authenticated user principal
     * @return a response entity containing the decryption result
     */
    @Override
    public final ResponseEntity<DecryptResponse> decryptPost(final DecryptRequest decryptRequest, final Principal principal) {
        final String clientName = this.resolveClientName(principal);
        logger.info("Received decrypt request for client '{}'", clientName);
        this.checkClientNameExists(clientName);

        this.decryptValidator.validateDecryptRequest(decryptRequest);
        logger.debug("Decrypt request validated for client '{}'", clientName);

        final ResponseEntity<DecryptResponse> response = this.decryptFacade.processDecryption(decryptRequest, clientName);
        logger.info("Decryption successful for client '{}'", clientName);
        return response;
    }

    /**
     * Handles key generation requests.
     *
     * @param principal the authenticated user principal
     * @return a response entity containing the generated key information
     */
    @Override
    public final ResponseEntity<GenerateKeyResponse> generateKeyPost(final Principal principal) {
        final String clientName = this.resolveClientName(principal);
        logger.info("Key generation requested by client '{}'", clientName);
        final ResponseEntity<GenerateKeyResponse> response = this.keyManagementFacade.generateKey(clientName);
        logger.info("Key successfully generated for client '{}'", clientName);
        return response;
    }

    /**
     * Handles JWT generation requests.
     *
     * @param generateJwtRequest the request containing parameters for JWT generation
     * @param principal          the authenticated user principal
     * @return a response entity containing the generated JWT
     */
    @Override
    public final ResponseEntity<GenerateJwtResponse> generateJwtPost(final GenerateJwtRequest generateJwtRequest, final Principal principal) {
        final String clientName = this.resolveClientName(principal);
        logger.info("JWT generation requested by client '{}'", clientName);
        this.checkClientNameExists(clientName);

        this.jwtManagementValidator.validateGenerateJwtRequest(generateJwtRequest);
        logger.debug("JWT request validated for client '{}'", clientName);

        final ResponseEntity<GenerateJwtResponse> response = this.jwtManagementFacade.generateJwt(generateJwtRequest, clientName);
        logger.info("JWT successfully generated for client '{}'", clientName);
        return response;
    }

    /**
     * Checks if the client name exists in the registry.
     *
     * @param clientName the name of the client to check
     * @throws BadRequestException if the client does not exist
     */
    // TODO update after new implementation of mtls
    private void checkClientNameExists(final String clientName) {
        if (!this.clientKeyRegistry.hasClient(clientName)) {
            final ErrorCode errorCode = ErrorCode.CLIENT_NOT_FOUND;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withUserMsgFormatted(clientName);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            this.customLogger.logError(errorDetail);
            throw new BadRequestException(errorDetail);
        }
        logger.debug("Client '{}' found in registry", clientName);
    }

    /**
     * Resolves the client name from the principal.
     *
     * @param principal the authenticated user principal
     * @return the name of the client
     */
    // TODO update after new implementation of mtls
    private String resolveClientName(final Principal principal) {
        final String clientName = (null != principal) ? principal.getName() : "anonymous-client";
        logger.debug("Resolved client name: '{}'", clientName);
        return clientName;
    }

    /**
     * Handles CSR signing requests.
     *
     * @param signCsrRequest the request containing the CSR to be signed
     * @return a response entity containing the signed CSR
     */
    // TODO delete after new implementation of mtls
    @Override
    public final ResponseEntity<SignCsrResponse> signCsrPost(final SignCsrRequest signCsrRequest) {
        logger.info("Received CSR signing request");
        return this.tlsManagementFacade.signCsr(signCsrRequest);
    }

    /**
     * Retrieves the root CA certificate.
     *
     * @return a response entity containing the root CA certificate
     */
    @Override
    public final ResponseEntity<GetRootCaCertResponse> rootCaGet() {
        logger.info("Root CA certificate requested");
        return this.tlsManagementFacade.getRootCaCert();
    }
}
