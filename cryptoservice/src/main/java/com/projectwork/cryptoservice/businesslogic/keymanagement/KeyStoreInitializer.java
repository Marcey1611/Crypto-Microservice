package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

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
        KeyStore keystore = keyStoreHelper.loadKeyStore();

        if (!checkContainsAlias("jwt-signing-key")) {
            System.out.println("Keystore enthält keinen JWT-Signing-Key. Neuer Key wird generiert...");
            initJwtSigningKey(keystore);
            System.out.println("JWT-Signing-Key erfolgreich im Keystore gespeichert!");
        } else {
            System.out.println("JWT-Signing-Key bereits im Keystore vorhanden.");
        }
        
        if (!checkContainsAlias("master-key")) {
            System.out.println("Keystore enthält keinen Master-Key. Neuer Key wird generiert...");
            initMasterKey(keystore);
            System.out.println("Master-Key erfolgreich im KeyStore gespeichert.");
        } else {
            System.out.println("Master-Key bereits im KeyStore vorhanden.");
        }
    }

    private boolean checkContainsAlias(final String alias) {
        final KeyStore keystore = keyStoreHelper.loadKeyStore();

        try {
            return keystore.containsAlias(alias);
        } catch (final KeyStoreException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_NOT_INITIALIZED.builder()
                    .withContext(String.format("While checking if alias '%s' exists in the keystore.", alias))
                    .withException(exception)
                    .build()
            );
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
    private void initJwtSigningKey(final KeyStore keystore) {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException exception) {
            throw new InternalServerErrorException(
                ErrorCode.JWT_SECURE_RANDOM_FAILED.builder()
                    .withContext("While creating SecureRandom instance for generating JWT signing key.")
                    .withException(exception)
                    .build()
            );
        }
    
        final KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("HmacSHA256");
        } catch (final NoSuchAlgorithmException exception) {
            throw new InternalServerErrorException(
                ErrorCode.JWT_KEYGEN_INIT_FAILED.builder()
                    .withContext("While creating KeyGenerator for JWT signing key.")
                    .withException(exception)
                    .build()
            );
        }
    
        try {
            keyGen.init(256, secureRandom);
        } catch (final InvalidParameterException exception) {
            throw new InternalServerErrorException(
                ErrorCode.JWT_KEYGEN_INIT_PARAMS_INVALID.builder()
                    .withContext("While initializing KeyGenerator with SecureRandom for JWT signing key.")
                    .withException(exception)
                    .build()
            );
        }
    
        final SecretKey signingKey = keyGen.generateKey();
        keyStoreHelper.storeKey("jwt-signing-key", signingKey); // Fehlerbehandlung findet dort statt
    }
    

    /**
     * 
     * @param keystore
     * @throws Exception
     * 
     * SecureCodingPractices:
     * - OWASP 104 Secure Random Number Generation: Key generation uses SecureRandom.getInstanceStrong() as cryptographical secure random source
     */
    private void initMasterKey(final KeyStore keyStore) {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException exception) {
            throw new InternalServerErrorException(
                ErrorCode.MASTER_KEY_SECURE_RANDOM_FAILED.builder()
                    .withContext("While creating SecureRandom for master key generation.")
                    .withException(exception)
                    .build()
            );
        }
    
        final KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (final NoSuchAlgorithmException exception) {
            throw new InternalServerErrorException(
                ErrorCode.MASTER_KEYGEN_INIT_FAILED.builder()
                    .withContext("While creating KeyGenerator for master key.")
                    .withException(exception)
                    .build()
            );
        }
    
        try {
            keyGen.init(256, secureRandom);
        } catch (final InvalidParameterException exception) {
            throw new InternalServerErrorException(
                ErrorCode.MASTER_KEYGEN_PARAMS_INVALID.builder()
                    .withContext("While initializing KeyGenerator with SecureRandom for master key.")
                    .withException(exception)
                    .build()
            );
        }
    
        final SecretKey masterKey = keyGen.generateKey();
        keyStoreHelper.storeKey("master-key", masterKey); // eigene Fehlerbehandlung dort
    }
    
}
