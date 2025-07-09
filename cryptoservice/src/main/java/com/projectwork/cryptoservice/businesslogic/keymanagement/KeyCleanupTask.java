package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * KeyCleanupTask is a scheduled task that periodically checks for expired keys in the keystore
 * and removes them, ensuring that the keystore remains clean and does not contain outdated keys.
 */
@RequiredArgsConstructor
@Component
public class KeyCleanupTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyCleanupTask.class);
    private static final String MASTER_KEY_ALIAS = "master-key";
    private static final String JWT_SIGNING_KEY_ALIAS = "jwt-signing-key";

    private final ClientKeyRegistry clientKeyRegistry;
    private final KeyExpirationChecker expirationChecker;
    private final KeyStoreLoader keyStoreLoader;

    /**
     * Scheduled method that runs every hour to clean up expired keys.
     */
    @Scheduled(fixedRate = 3600000L)
    public final void cleanupKeysPeriodically() {
        LOGGER.info("Running scheduled key cleanup task");
        this.cleanupExpiredKeys();
    }

    /**
     * Method to manually trigger the cleanup of expired keys.
     */
    public final void cleanupExpiredKeys() {
        LOGGER.debug("Starting manual cleanup of expired keys");
        final KeyStore keystore = this.keyStoreLoader.load();
        final List<String> expiredAliases = this.findExpiredAliases(keystore);
        LOGGER.info("Found {} expired keys", expiredAliases.size());
        this.deleteExpiredKeys(keystore, expiredAliases);
        this.keyStoreLoader.save(keystore);
        LOGGER.info("Key cleanup task completed successfully");
    }

    /**
     * Finds all expired aliases in the provided KeyStore.
     * It skips reserved aliases that should not be deleted.
     *
     * @param keystore the KeyStore to check for expired keys
     * @return a list of aliases that are expired
     */
    private List<String> findExpiredAliases(final KeyStore keystore) {
        final List<String> expired = new ArrayList<>();
        final Enumeration<String> aliases = this.getAliases(keystore);
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (this.isReservedAlias(alias)) continue;
            if (this.expirationChecker.isExpired(keystore, alias)) {
                LOGGER.debug("Key with alias '{}' is expired", alias);
                expired.add(alias);
            }
        }
        return expired;
    }

    /**
     * Retrieves all aliases from the KeyStore.
     * If an error occurs while retrieving aliases, it logs the error and throws an InternalServerErrorException.
     *
     * @param keystore the KeyStore from which to retrieve aliases
     * @return an Enumeration of aliases in the KeyStore
     */
    private Enumeration<String> getAliases(final KeyStore keystore) {
        try {
            return keystore.aliases();
        } catch (final KeyStoreException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_NOT_INITIALIZED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While loading aliases in cleanup task.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }
    }

    /**
     * Checks if the provided alias is a reserved alias that should not be deleted.
     *
     * @param alias the alias to check
     * @return true if the alias is reserved, false otherwise
     */
    private boolean isReservedAlias(final String alias) {
        return MASTER_KEY_ALIAS.equals(alias) || JWT_SIGNING_KEY_ALIAS.equals(alias);
    }

    /**
     * Deletes expired keys from the KeyStore and removes them from the ClientKeyRegistry.
     * It logs each deletion and handles any exceptions that occur during the deletion process.
     *
     * @param keystore         the KeyStore from which to delete expired keys
     * @param aliasesToDelete  a list of aliases to delete from the KeyStore
     */
    private void deleteExpiredKeys(final KeyStore keystore, final List<String> aliasesToDelete) {
        for (final String alias : aliasesToDelete) {
            try {
                keystore.deleteEntry(alias);
                this.clientKeyRegistry.removeClientByKeyAlias(alias);
                LOGGER.info("Deleted expired key '{}'", alias);
            } catch (final KeyStoreException exception) {
                final ErrorCode errorCode = ErrorCode.DELETING_KEYSTORE_ENTRY_FAILED;
                final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
                errorDetailBuilder.withContext("While deleting key for alias: " + alias);
                errorDetailBuilder.withException(exception);
                final ErrorDetail errorDetail = errorDetailBuilder.build();
                errorDetail.logErrorWithException();
                throw new InternalServerErrorException(errorDetail);
            }
        }
    }
}
