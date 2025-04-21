package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * SecureCodingPractices:
 * - OWASP [106] Implements part of the key lifecycle management (expiration/cleanup).
 * - OWASP [102] Protect secrets by cleaning up expired client keys.
 * - OWASP [199] Resource handling (KeyStore and PasswordProtection destroyed properly).
 */
@Component
public class KeyCleanupTask {
    
    private final KeyStoreHelper keyStoreHelper;
    private final ClientKeyDataMap clientKeyAliasMap;

    public KeyCleanupTask(KeyStoreHelper keyStoreHelper, ClientKeyDataMap clientKeyAliasMap) {
        this.keyStoreHelper = keyStoreHelper;
        this.clientKeyAliasMap = clientKeyAliasMap;
    }

    @Scheduled(fixedRate = 3600000)
    public void cleanupKeysPeriodically() {
        try {
            System.out.println("Starte periodischen Key Cleanup...");
            cleanupExpiredKeys();
            System.out.println("Key Cleanup abgeschlossen.");
        } catch (Exception e) {
            System.err.println("Fehler beim Key Cleanup: " + e.getMessage());
        }
    }

    public void cleanupExpiredKeys() throws Exception {
        final KeyStore keystore = keyStoreHelper.loadKeyStore();
        final long expirationTimeMillis = TimeUnit.HOURS.toMillis(1);
        final long now = System.currentTimeMillis();
        final List<String> toDelete = new ArrayList<>();
        if (!keystore.aliases().hasMoreElements()) {
            System.out.println("Keine Client-Schlüssel gefunden. Key Cleanup nicht notwendig.");
            return;
        }
        final Enumeration<String> aliases = keystore.aliases();

        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if ("master-key".equals(alias) || "jwt-signing-key".equals(alias)) continue;
            String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
            final char[] passwordChars = keystorePassword.toCharArray();
            keystorePassword = null;
            final PasswordProtection passwordProtection = new PasswordProtection(passwordChars);
            Arrays.fill(passwordChars, '\0');
            try {
                final KeyStore.Entry entry = keystore.getEntry(alias, passwordProtection);
                if (entry instanceof KeyStore.SecretKeyEntry) {
                    final long creationTime = keystore.getCreationDate(alias).getTime();
                    if (now - creationTime > expirationTimeMillis) {
                        toDelete.add(alias);
                    }
                }
            } finally {
                passwordProtection.destroy(); //Passwort aus speicher löschen ist nur solange drin wie nötig
            }  
        }

        for (String alias : toDelete) {
            keystore.deleteEntry(alias);
            clientKeyAliasMap.removeKeyAliasFromMap(alias);
            System.out.println("Client Key gelöscht: " + alias);
        }
        keyStoreHelper.saveKeyStore(keystore);
    }
}
