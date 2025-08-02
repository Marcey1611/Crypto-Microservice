package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
 *
 * SCPs:
 * - [114] Logging controls should support both success and failure of specified security events
 */
@RequiredArgsConstructor
@Component
public class KeyCleanupTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyCleanupTask.class);

    private final ClientKeyRegistry clientKeyRegistry;
    private final KeyExpirationChecker expirationChecker;
    private final KeyStoreLoader keyStoreLoader;
    private final ErrorHandler errorHandler;

    @Value("${client.keystore.path}")
    private String clientKeystorePath;

    @Value("${client.keystore.password}")
    private String clientKeystorePassword;

    /**
     * Scheduled method that runs every hour to clean up expired keys.
     */
    @Scheduled(fixedRate = 60000L)
    public final void cleanupKeysPeriodically() {
        LOGGER.info("Running scheduled key cleanup task");
        this.cleanupExpiredKeys();
    }

    /**
     * Method to manually trigger the cleanup of expired keys.
     */
    public final void cleanupExpiredKeys() {
        LOGGER.debug("Starting manual cleanup of expired keys");
        final KeyStore keystore = this.keyStoreLoader.load(this.clientKeystorePath, this.clientKeystorePassword);
        final List<String> expiredAliases = this.findExpiredAliases(keystore);
        LOGGER.info("Found {} expired keys", expiredAliases.size());
        this.deleteExpiredKeys(keystore, expiredAliases);
        this.keyStoreLoader.save(keystore, this.clientKeystorePath, this.clientKeystorePassword);
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
            if (this.expirationChecker.isExpired(keystore, alias, this.clientKeystorePassword)) {
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
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.KEYSTORE_NOT_INITIALIZED,
            "While loading aliases in cleanup task.",
                    exception
            );
        }
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
                LOGGER.info("Deleted expired key successfully.");
            } catch (final KeyStoreException exception) {
                throw this.errorHandler.handleBusinessError(
                        ErrorCode.DELETING_KEYSTORE_ENTRY_FAILED,
                        "While deleting key.",
                        exception
                );
            }
        }
    }
}
