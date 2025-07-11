package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * SecureCodingPractices:
 * - OWASP [102] Master secret (KeyStore) protection
 * - OWASP [106] Centralized key storage and retrieval logic (KeyStore as secure container)
 * - OWASP [194] Carefully handle sensitive data (keystore password), wiping char arrays after use
 */
@Component
@RequiredArgsConstructor
public class MasterKeyService {

    private static final Logger LOGGER = LoggerFactory.getLogger(MasterKeyService.class);

    private final ErrorHandler errorHandler;

    /**
     * Retrieves the master key from the provided KeyStore.
     *
     * @param keystore the KeyStore instance from which to retrieve the master key
     * @return the retrieved SecretKey representing the master key
     * @throws InternalServerErrorException if there is an error accessing the master key
     */
    public final SecretKey retrieveMasterKey(final KeyStore keystore) {
        LOGGER.debug("Retrieving master key from KeyStore");

        final String password = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = password.toCharArray();

        try {
            final SecretKey masterKey = (SecretKey) keystore.getKey("master-key", passwordChars);
            if (null == masterKey) {
                throw this.errorHandler.handleError(
                        ErrorCode.MASTER_KEY_MISSING,
                        "Master key is missing in keystore."
                );
            }

            LOGGER.info("Master key successfully retrieved from KeyStore");
            return masterKey;

        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            throw this.errorHandler.handleError(
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

