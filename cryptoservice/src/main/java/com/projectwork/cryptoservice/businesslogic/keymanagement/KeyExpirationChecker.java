package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.security.auth.DestroyFailedException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * KeyCleanupTask is a scheduled task that periodically checks for expired keys in the keystore
 * and removes them, ensuring that the keystore remains clean and does not contain outdated keys.
 */
@Component
@RequiredArgsConstructor
public class KeyExpirationChecker {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyExpirationChecker.class);
    private static final long EXPIRATION_TIME_MILLIS = TimeUnit.HOURS.toMillis(1);
    private static final String ENV_KEYSTORE_PASSWORD = "KEYSTORE_PASSWORD";

    /**
     * Checks if a key with the given alias in the provided keystore is expired.
     */
    public final boolean isExpired(final KeyStore keystore, final String alias) {
        LOGGER.debug("Checking expiration status for alias '{}'", alias);
        final KeyStore.Entry entry = this.getEntry(keystore, alias);
        if (!(entry instanceof KeyStore.SecretKeyEntry)) {
            LOGGER.debug("Alias '{}' is not a SecretKeyEntry – skipping expiration check", alias);
            return false;
        }
        final Date creationDate = this.getCreationDate(keystore, alias);
        final long ageMillis = System.currentTimeMillis() - creationDate.getTime();
        final boolean expired = ageMillis > EXPIRATION_TIME_MILLIS;
        LOGGER.debug("Alias '{}' created at {}, expired: {}", alias, creationDate, expired);
        return expired;
    }

    /**
     * Retrieves KeyStore.Entry for the specified alias using password protection.
     */
    private KeyStore.Entry getEntry(final KeyStore keystore, final String alias) {
        final String envKeystorePassword = System.getenv(ENV_KEYSTORE_PASSWORD);
        final char[] passwordChars = Optional.ofNullable(envKeystorePassword)
                .map(String::toCharArray)
                .orElse(new char[0]);
        final PasswordProtection protection = new PasswordProtection(passwordChars);
        Arrays.fill(passwordChars, '\0');

        try {
            return keystore.getEntry(alias, protection);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException exception) {
            final ErrorCode errorCode = ErrorCode.GETTING_KEYSTORE_ENTRY_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While getting entry for alias: " + alias);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        } finally {
            this.destroyProtection(protection, alias);
        }
    }

    /**
     * Retrieves the creation date of the key with the given alias in the provided keystore.
     */
    private Date getCreationDate(final KeyStore keystore, final String alias) {
        try {
            return keystore.getCreationDate(alias);
        } catch (final KeyStoreException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_NOT_INITIALIZED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While getting creation date for alias: " + alias);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }
    }

    /**
     * Destroys the given PasswordProtection instance securely.
     */
    private void destroyProtection(final PasswordProtection protection, final String alias) {
        try {
            protection.destroy();
        } catch (final DestroyFailedException exception) {
            final ErrorCode errorCode = ErrorCode.PASSWORD_DESTROY_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While destroying protection for alias: " + alias);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }
    }
}
