package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
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

    private final ErrorHandler errorHandler;

    /**
     * Checks if the key with the given alias in the provided keystore is expired.
     * A key is considered expired if it was created more than 1 hour ago.
     *
     * @param keystore the KeyStore instance containing the keys
     * @param alias    the alias of the key to check
     * @return true if the key is expired, false otherwise
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
     * Retrieves the KeyStore.Entry for the given alias from the provided keystore.
     * It uses the keystore password from the environment variable "KEYSTORE_PASSWORD".
     *
     * @param keystore the KeyStore instance to retrieve the entry from
     * @param alias    the alias of the key to retrieve
     * @return the KeyStore.Entry for the specified alias
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
            final String context = "While getting entry for alias: " + alias;
            throw this.errorHandler.handleError(
                    ErrorCode.GETTING_KEYSTORE_ENTRY_FAILED,
                    context,
                    exception
            );
        } finally {
            this.destroyProtection(protection, alias);
        }
    }

    /**
     * Retrieves the creation date of the key associated with the given alias in the provided keystore.
     *
     * @param keystore the KeyStore instance containing the keys
     * @param alias    the alias of the key to get the creation date for
     * @return the creation date of the key
     */
    private Date getCreationDate(final KeyStore keystore, final String alias) {
        try {
            return keystore.getCreationDate(alias);
        } catch (final KeyStoreException exception) {
            final String context = "While getting creation date for alias: " + alias;
            throw this.errorHandler.handleError(
                    ErrorCode.KEYSTORE_NOT_INITIALIZED,
                    context,
                    exception
            );
        }
    }

    /**
     * Destroys the PasswordProtection instance to free up resources.
     * This is called after retrieving the KeyStore.Entry to ensure that sensitive data is cleared.
     *
     * @param protection the PasswordProtection instance to destroy
     * @param alias      the alias of the key for which the protection is being destroyed
     */
    private void destroyProtection(final PasswordProtection protection, final String alias) {
        try {
            protection.destroy();
        } catch (final DestroyFailedException exception) {
            final String context = "While destroying protection for alias: " + alias;
            throw this.errorHandler.handleError(
                    ErrorCode.PASSWORD_DESTROY_FAILED,
                    context,
                    exception
            );
        }
    }
}
