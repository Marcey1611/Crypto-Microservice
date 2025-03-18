package com.projectwork.cryptoservice.businesslogic;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class KeyCleanupTask {
    
    private final KeyStoreHelper keyStoreHelper;

    @Value("${keystore.password}")
    private String keystorePassword;

    public KeyCleanupTask(KeyStoreHelper keyStoreHelper) {
        this.keyStoreHelper = keyStoreHelper;
    }

    @Scheduled(fixedRate = 60000)
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
        final long expirationTimeMillis = TimeUnit.MINUTES.toMillis(10);
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
            final PasswordProtection passwordProtection = new PasswordProtection(keystorePassword.toCharArray());
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
            System.out.println("Client Key gelöscht: " + alias);
        }
        keyStoreHelper.saveKeyStore(keystore);
    }
}
