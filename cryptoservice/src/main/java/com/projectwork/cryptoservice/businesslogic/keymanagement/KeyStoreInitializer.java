package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.security.KeyStore;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;

/**
 * 
 * SecureCodingPractices
 * - OWASP [101] Crypto operations (key gen) on trusted server
 * - OWASP [104] Secure Random for all key generations
 * - OWASP [106] Key management initialization (ensures master and signing keys)
 */
@RequiredArgsConstructor
@Component
public class KeyStoreInitializer {
    private final KeyStoreHelper keyStoreHelper;

    // OWASP [102] Ensuring master secrets (master-key & jwt-signing-key) are protected and initialized
    @PostConstruct
    public void initKeyStore() {
        try {
            KeyStore keystore = keyStoreHelper.loadKeyStore();

            if (!keystore.containsAlias("jwt-signing-key")) {
                System.out.println("Keystore enthält keinen JWT-Signing-Key. Neuer Key wird generiert...");
                initJwtSigningKey(keystore);
                System.out.println("JWT-Signing-Key erfolgreich im Keystore gespeichert!");
            } else {
                System.out.println("JWT-Signing-Key bereits im Keystore vorhanden.");
            }
            
            if (!keystore.containsAlias("master-key")) {
                System.out.println("Keystore enthält keinen Master-Key. Neuer Key wird generiert...");
                initMasterKey(keystore);
                System.out.println("Master-Key erfolgreich im KeyStore gespeichert.");
            } else {
                System.out.println("Master-Key bereits im KeyStore vorhanden.");
            }
        } catch (final Exception exception) {
            throw new RuntimeException("Fehler beim Initialisieren des Keystores!", exception);
        }
    }

    /**
     * 
     * @param keystore
     * @throws Exception
     * 
     * SecureCodingPractices:
     * - OWASP 104 Secure Random Number Generation: Key generation uses SecureRandom.getInstanceStrong() as cryptographical secure random source
     */
    private void initJwtSigningKey(final KeyStore keystore) throws Exception {
        final SecureRandom secureRandom = SecureRandom.getInstanceStrong(); 
        final KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        keyGen.init(256, secureRandom); // [104] SecureRandom for signing key
        final SecretKey signingKey = keyGen.generateKey();
        keyStoreHelper.storeKey("jwt-signing-key", signingKey);
    }

    /**
     * 
     * @param keystore
     * @throws Exception
     * 
     * SecureCodingPractices:
     * - OWASP 104 Secure Random Number Generation: Key generation uses SecureRandom.getInstanceStrong() as cryptographical secure random source
     */
    private void initMasterKey(final KeyStore keyStore) throws Exception {
        final SecureRandom secureRandom = SecureRandom.getInstanceStrong(); 
        final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, secureRandom); // [104] SecureRandom for master key
        final SecretKey masterKey = keyGen.generateKey();
        keyStoreHelper.storeKey("master-key", masterKey);
    }
}
