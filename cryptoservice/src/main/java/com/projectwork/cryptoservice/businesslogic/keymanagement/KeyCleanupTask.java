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

    private final KeyStoreHelper keyStoreHelper;
    private final ClientKeyRegistry clientKeyRegistry;
    private final KeyExpirationChecker expirationChecker;
    private final KeyStoreLoader keyStoreLoader;

    /**
     * Scheduled method that runs every hour to clean up expired keys.
     * It retrieves the keystore, finds expired keys, and deletes them.
     */
    @Scheduled(fixedRate = 3600000L)
    public final void cleanupKeysPeriodically() {
        this.cleanupExpiredKeys();
    }

    /**
     * Method to manually trigger the cleanup of expired keys.
     * This can be called from other parts of the application if needed.
     */
    public final void cleanupExpiredKeys() {
        final KeyStore keystore = this.keyStoreLoader.load();
        final List<String> expiredAliases = this.findExpiredAliases(keystore);
        this.deleteExpiredKeys(keystore, expiredAliases);
        this.keyStoreLoader.save(keystore);
    }

    /**
     * Finds all expired keys in the provided keystore.
     *
     * @param keystore the KeyStore to check for expired keys
     * @return a list of aliases for expired keys
     */
    private List<String> findExpiredAliases(final KeyStore keystore) {
        final List<String> expired = new ArrayList<>();
        final Enumeration<String> aliases = this.getAliases(keystore);
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (this.isReservedAlias(alias)) continue;
            if (this.expirationChecker.isExpired(keystore, alias)) {
                expired.add(alias);
            }
        }
        return expired;
    }

    /**
     * Retrieves all aliases from the provided KeyStore.
     *
     * @param keystore the KeyStore from which to retrieve aliases
     * @return an Enumeration of aliases
     * @throws InternalServerErrorException if there is an error retrieving aliases
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
            throw new InternalServerErrorException(errorDetail);
        }
    }

    /**
     * Checks if the given alias is a reserved alias that should not be deleted.
     *
     * @param alias the alias to check
     * @return true if the alias is reserved, false otherwise
     */
    private boolean isReservedAlias(final String alias) {
        return MASTER_KEY_ALIAS.equals(alias) || JWT_SIGNING_KEY_ALIAS.equals(alias);
    }

    /**
     * Deletes expired keys from the KeyStore and removes them from the ClientKeyRegistry.
     *
     * @param keystore the KeyStore from which to delete expired keys
     * @param aliasesToDelete a list of aliases for keys to be deleted
     * @throws InternalServerErrorException if there is an error deleting keys
     */
    private void deleteExpiredKeys(final KeyStore keystore, final List<String> aliasesToDelete) {
        for (final String alias : aliasesToDelete) {
            try {
                keystore.deleteEntry(alias);
                this.clientKeyRegistry.removeClientByKeyAlias(alias);
            } catch (final KeyStoreException exception) {
                final ErrorCode errorCode = ErrorCode.DELETING_KEYSTORE_ENTRY_FAILED;
                final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
                errorDetailBuilder.withContext("While deleting key for alias: " + alias);
                errorDetailBuilder.withException(exception);
                final ErrorDetail errorDetail = errorDetailBuilder.build();
                throw new InternalServerErrorException(errorDetail);
            }
        }
    }
}

