package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import javax.security.auth.DestroyFailedException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class KeyCleanupTask {
    private static final Logger logger = LoggerFactory.getLogger(KeyCleanupTask.class);

    private static final String MASTER_KEY_ALIAS = "master-key";
    private static final String JWT_SIGNING_KEY_ALIAS = "jwt-signing-key";
    private static final String ENV_KEYSTORE_PASSWORD = "KEYSTORE_PASSWORD";
    private static final long EXPIRATION_TIME_MILLIS = TimeUnit.HOURS.toMillis(1);

    private final KeyStoreHelper keyStoreHelper;
    private final ClientKeyRegistry clientKeyRegistry;

    @Scheduled(fixedRate = 3600000)
    public void cleanupKeysPeriodically() {
        logger.info("Starte periodischen Key Cleanup...");
        cleanupExpiredKeys();
        logger.info("Key Cleanup abgeschlossen.");
    }

    public void cleanupExpiredKeys() {
        final KeyStore keystore = keyStoreHelper.loadKeyStore();
        final List<String> expiredAliases = findExpiredAliases(keystore);
        deleteExpiredKeys(keystore, expiredAliases);
        keyStoreHelper.saveKeyStore(keystore);
    }

    private List<String> findExpiredAliases(final KeyStore keystore) {
        final long now = System.currentTimeMillis();
        final List<String> expiredAliases = new ArrayList<>();

        final Optional<Enumeration<String>> aliasesOpt = loadAliases(keystore);
        if (aliasesOpt.isEmpty()) return expiredAliases;

        final Enumeration<String> aliases = aliasesOpt.get();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (isReservedAlias(alias)) continue;
            if (isKeyExpired(keystore, alias, now)) {
                expiredAliases.add(alias);
            }
        }
        return expiredAliases;
    }

    private Optional<Enumeration<String>> loadAliases(final KeyStore keystore) {
        Enumeration<String> aliases;
        try {
            aliases = keystore.aliases();
        } catch (final KeyStoreException exception) {
            throw new InternalServerErrorException(ErrorCode.KEYSTORE_NOT_INITIALIZED.builder()
                .withContext("While trying to load the aliasses of the keystore in key cleanup." )
                .withException(exception)
                .build()
            );
        }
        if (!aliases.hasMoreElements()) {
            return Optional.empty();
        }
        return Optional.of(aliases);
    }

    private boolean isReservedAlias(final String alias) {
        return MASTER_KEY_ALIAS.equals(alias) || JWT_SIGNING_KEY_ALIAS.equals(alias);
    }

    private boolean isKeyExpired(final KeyStore keystore, final String alias, final long now) {
        final char[] passwordChars = getPasswordChars();
        final PasswordProtection passwordProtection = new PasswordProtection(passwordChars);
        Arrays.fill(passwordChars, '\0');

        KeyStore.Entry entry;
        try {
            entry = keystore.getEntry(alias, passwordProtection);
        } catch (final NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException exception) {
            throw new InternalServerErrorException(
                ErrorCode.GETTING_KEYSTORE_ENTRY_FAILED.builder()
                    .withContext(String.format("While trying to retrieve key entry for alias '%s' from the keystore in expiration check.", alias))
                    .withException(exception)
                    .build()
            );
        } finally {
            try {
                passwordProtection.destroy();
            } catch (final DestroyFailedException exception) {
                throw new InternalServerErrorException(
                    ErrorCode.PASSWORD_DESTROY_FAILED.builder()
                        .withContext(String.format("While destroying PasswordProtection after key expiration check for alias '%s'.", alias))
                        .withException(exception)
                        .build()
                );
            }
        }
        
        if (entry instanceof KeyStore.SecretKeyEntry) {
            long creationTime;
            try {
                creationTime = keystore.getCreationDate(alias).getTime();
            } catch (final KeyStoreException exception) {
                throw new InternalServerErrorException(ErrorCode.KEYSTORE_NOT_INITIALIZED.builder()
                    .withContext("While trying to get the creation date of a key in a keystore. While checking if the key is expired.")
                    .withException(exception)
                    .build()
                );
            }   
            return now - creationTime > EXPIRATION_TIME_MILLIS;
        }
        return false;
    }

    private void deleteExpiredKeys(final KeyStore keystore, final List<String> aliasesToDelete) {
        for (final String alias : aliasesToDelete) {
            try {
                keystore.deleteEntry(alias);
            } catch (final KeyStoreException exception) {
                throw new InternalServerErrorException(
                    ErrorCode.DELETING_KEYSTORE_ENTRY_FAILED.builder()
                        .withContext(String.format("While trying to delete the key with alias '%s' from the keystore.", alias))
                        .withException(exception)
                        .build()
                );
            }
            clientKeyRegistry.removeClientByKeyAlias(alias);
            logger.info("Client Key gelöscht: {}", alias);
        }
    }

    private char[] getPasswordChars() {
        final String keystorePassword = System.getenv(ENV_KEYSTORE_PASSWORD);
        return keystorePassword != null ? keystorePassword.toCharArray() : new char[0];
    }
}
