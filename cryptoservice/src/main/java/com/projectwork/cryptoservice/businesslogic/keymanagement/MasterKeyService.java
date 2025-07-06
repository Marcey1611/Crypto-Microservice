package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
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
public class MasterKeyService {

    private static final Logger LOGGER = LoggerFactory.getLogger(MasterKeyService.class);

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
                final ErrorCode errorCode = ErrorCode.MASTER_KEY_MISSING;
                final ErrorDetailBuilder builder = errorCode.builder();
                builder.withContext("Master key is missing in keystore.");
                final ErrorDetail errorDetail = builder.build();
                errorDetail.logErrorWithException();
                throw new InternalServerErrorException(errorDetail);
            }

            LOGGER.info("Master key successfully retrieved from KeyStore");
            return masterKey;

        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_KEY_ACCESS_FAILED;
            final ErrorDetailBuilder builder = errorCode.builder();
            builder.withContext("Error accessing master key from keystore.");
            builder.withLogMsgFormatted("master-key");
            builder.withException(exception);
            final ErrorDetail errorDetail = builder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [194]
        }
    }
}

