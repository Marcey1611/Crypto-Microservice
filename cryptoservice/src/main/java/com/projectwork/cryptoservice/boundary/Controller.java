package com.projectwork.cryptoservice.boundary;

import com.projectwork.cryptoservice.boundary.api.DecryptAPI;
import com.projectwork.cryptoservice.boundary.api.EncryptAPI;
import com.projectwork.cryptoservice.boundary.api.JwtManagementAPI;
import com.projectwork.cryptoservice.boundary.api.KeyManagementAPI;
import com.projectwork.cryptoservice.boundary.authorization.AuthService;
import com.projectwork.cryptoservice.boundary.validation.ValidationService;
import com.projectwork.cryptoservice.businessfacade.DecryptFacade;
import com.projectwork.cryptoservice.businessfacade.EncryptFacade;
import com.projectwork.cryptoservice.businessfacade.JwtManagementFacade;
import com.projectwork.cryptoservice.businessfacade.KeyManagementFacade;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptRequest;
import com.projectwork.cryptoservice.entity.models.decrypt.DecryptResponse;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptRequest;
import com.projectwork.cryptoservice.entity.models.encrypt.EncryptResponse;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtRequest;
import com.projectwork.cryptoservice.entity.models.jwtmanagement.GenerateJwtResponse;
import com.projectwork.cryptoservice.entity.models.keymanagement.GenerateKeyResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/** * Controller class that handles incoming requests for encryption, decryption,
 * key management, JWT management, and TLS management.
 * It uses various facades to process the requests and returns appropriate responses.
 *
 * SCPs:
 * - [2] Identify all data sources and classify them into trusted and untrusted. Validate all data from untrusted sources
 * - [8] Validate all client-provided data before processing
 * - [87] Restrict access to services to only authorized users
 * - [88] Restrict access to application data to only authorized users
 * - [114] Logging controls should support both success and failure of specified security events
 */
@RequiredArgsConstructor
@RestController
public class Controller implements EncryptAPI, DecryptAPI, KeyManagementAPI, JwtManagementAPI {

    private static final Logger LOGGER = LoggerFactory.getLogger(Controller.class);

    private final EncryptFacade encryptFacade;
    private final DecryptFacade decryptFacade;
    private final KeyManagementFacade keyManagementFacade;
    private final JwtManagementFacade jwtManagementFacade;
    private final ValidationService validationService;
    private final AuthService authService;

    @Value("${master.keystore.path}")
    private String masterKeystorePath;

    @Value("${master.keystore.password}")
    private String masterKeystorePassword;

    /**
     * Handles key generation requests.
     *
     * @param principal the authenticated user principal
     * @return a response entity containing the generated key information
     */
    @Override
    public final ResponseEntity<GenerateKeyResponse> generateKeyPost(final Principal principal) {
        final String clientName = principal.getName();
        LOGGER.info("Key generation requested by client '{}'.", clientName);

        final ResponseEntity<GenerateKeyResponse> response = this.keyManagementFacade.generateKey(clientName);
        LOGGER.info("Key successfully generated for client '{}'.\n\n\n", clientName);
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
        final String clientName = principal.getName();
        LOGGER.info("JWT generation requested by client '{}'.", clientName);

        this.validationService.validateGenerateJwtRequest(generateJwtRequest);
        LOGGER.debug("JWT request validated for client '{}'.", clientName);

        this.authService.authGenerateJwtRequest(clientName);
        LOGGER.debug("Authorization successful for JWT generation request by client '{}'.", clientName);

        final ResponseEntity<GenerateJwtResponse> response = this.jwtManagementFacade.generateJwt(generateJwtRequest, clientName);
        LOGGER.info("JWT successfully generated for client '{}'.\n\n\n", clientName);
        return response;
    }

    /**
     * Handles encryption requests.
     *
     * @param encryptRequest the request containing the data to be encrypted
     * @param principal      the authenticated user principal
     * @return a response entity containing the encryption result
     */
    @Override
    public final ResponseEntity<EncryptResponse> encryptPost(final EncryptRequest encryptRequest, final Principal principal) {
        final String clientName = principal.getName();
        LOGGER.info("Received encrypt request for client '{}'.", clientName);

        this.validationService.validateEncryptRequest(encryptRequest, this.masterKeystorePath, this.masterKeystorePassword);
        LOGGER.debug("Encrypt request validated for client '{}'.", clientName);

        this.authService.authEncryptRequest(encryptRequest, clientName);
        LOGGER.debug("Authorization successful for encrypt request by client '{}'.", clientName);

        final ResponseEntity<EncryptResponse> response = this.encryptFacade.processEncryption(encryptRequest, clientName);
        LOGGER.info("Encryption successful for client '{}'\n\n\n", clientName);
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
        final String clientName = principal.getName();
        LOGGER.info("Received decrypt request for client '{}'.", clientName);

        this.validationService.validateDecryptRequest(decryptRequest, this.masterKeystorePath, this.masterKeystorePassword);
        LOGGER.debug("Decrypt request validated for client '{}'.", clientName);

        this.authService.authDecryptRequest(decryptRequest, clientName);
        LOGGER.debug("Authorization successful for decrypt request by client '{}'.", clientName);

        final ResponseEntity<DecryptResponse> response = this.decryptFacade.processDecryption(decryptRequest, clientName);
        LOGGER.info("Decryption successful for client '{}'.\n\n\n", clientName);
        return response;
    }
}
