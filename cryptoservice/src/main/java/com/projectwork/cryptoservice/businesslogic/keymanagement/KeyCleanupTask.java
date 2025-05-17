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
        try {
            cleanupExpiredKeys();
        } catch (Exception e) {
            logger.error("Fehler beim Key Cleanup", e);
        }
        logger.info("Key Cleanup abgeschlossen.");
    }

    public void cleanupExpiredKeys() {
        final KeyStore keystore = keyStoreHelper.loadKeyStore();
        try {
            final List<String> expiredAliases = findExpiredAliases(keystore);
            deleteExpiredKeys(keystore, expiredAliases);
        } finally {
            keyStoreHelper.saveKeyStore(keystore);
        }
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
        try {
            final Enumeration<String> aliases = keystore.aliases();
            if (!aliases.hasMoreElements()) {
                logger.info("Keine Client-Schlüssel gefunden. Key Cleanup nicht notwendig.");
                return Optional.empty();
            }
            return Optional.of(aliases);
        } catch (final KeyStoreException exception) {
            logger.error("Fehler beim Laden der Aliase aus dem KeyStore", exception);
            return Optional.empty();
        }
    }

    private boolean isReservedAlias(final String alias) {
        return MASTER_KEY_ALIAS.equals(alias) || JWT_SIGNING_KEY_ALIAS.equals(alias);
    }

    private boolean isKeyExpired(final KeyStore keystore, final String alias, final long now) {
        final char[] passwordChars = getPasswordChars();
        final PasswordProtection passwordProtection = new PasswordProtection(passwordChars);
        Arrays.fill(passwordChars, '\0');

        try {
            final KeyStore.Entry entry = keystore.getEntry(alias, passwordProtection);
            if (entry instanceof KeyStore.SecretKeyEntry) {
                final long creationTime = keystore.getCreationDate(alias).getTime();
                return now - creationTime > EXPIRATION_TIME_MILLIS;
            }
        } catch (final NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException exception) {
            logger.warn("Fehler beim Prüfen der Schlüsselexpiration für Alias: {}", alias, exception);
        } finally {
            try {
                passwordProtection.destroy();
            } catch (final DestroyFailedException exception) {
                logger.warn("Fehler beim Zerstören des PasswordProtection-Objekts", exception);
            }
        }
        return false;
    }

    private void deleteExpiredKeys(final KeyStore keystore, final List<String> aliasesToDelete) {
        for (final String alias : aliasesToDelete) {
            try {
                keystore.deleteEntry(alias);
                clientKeyRegistry.removeClientByKeyAlias(alias);
                logger.info("Client Key gelöscht: {}", alias);
            } catch (final KeyStoreException exception) {
                logger.warn("Fehler beim Löschen des Eintrags für Alias: {}", alias, exception);
            }
        }
    }

    private char[] getPasswordChars() {
        final String keystorePassword = System.getenv(ENV_KEYSTORE_PASSWORD);
        return keystorePassword != null ? keystorePassword.toCharArray() : new char[0];
    }
}
