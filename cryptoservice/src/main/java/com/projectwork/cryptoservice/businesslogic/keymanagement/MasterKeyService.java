package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;

/**
 * MasterKeyService is responsible for retrieving the master key from the KeyStore.
 * It ensures that the master key is securely accessed and handles any exceptions that may occur.
 * SCPs:
 * - [114] Logging controls should support both success and failure of specified security events
 */
@Component
@RequiredArgsConstructor
public class MasterKeyService {

    private static final Logger LOGGER = LoggerFactory.getLogger(MasterKeyService.class);

    private final ErrorHandler errorHandler;
    private final KeyStoreLoader loader;

    @Value("${master.keystore.path}")
    private String masterKeystorePath;

    @Value("${master.keystore.password}")
    private String masterKeystorePassword;

    /**
     * Retrieves the master key from the provided KeyStore.
     *
     * @return the retrieved SecretKey representing the master key
     * @throws InternalServerErrorException if there is an error accessing the master key
     */
    public final SecretKey retrieveMasterKey() {
        LOGGER.debug("Retrieving master key from KeyStore");
        final KeyStore keystore = this.loader.load(this.masterKeystorePath, this.masterKeystorePassword);
        final char[] passwordChars = this.masterKeystorePassword.toCharArray();

        try {
            final SecretKey masterKey = (SecretKey) keystore.getKey("master-key", passwordChars);
            if (null == masterKey) {
                throw this.errorHandler.handleClientError(
                        ErrorCode.MASTER_KEY_MISSING,
                        "Master key is missing in keystore."
                );
            }

            LOGGER.info("Master key successfully retrieved from KeyStore");
            return masterKey;

        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.KEYSTORE_KEY_ACCESS_FAILED,
                    "master-key",
                    "Error accessing master key from keystore.",
                    exception
            );
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [194]
        }
    }
}

