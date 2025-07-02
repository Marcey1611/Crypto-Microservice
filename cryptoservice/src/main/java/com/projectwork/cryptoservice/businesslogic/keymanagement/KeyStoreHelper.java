package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

//TODO Refactor -> to long, methods to long and complex extend with helper classes or split in separate classes
/**
 * KeyStoreHelper is a utility class for managing cryptographic keys in a secure manner.
 * SecureCodingPractices
 * - OWASP [102] Master secret (KeyStore) protection
 * - OWASP [106] Centralized key storage and retrieval logic (KeyStore as secure container)
 * - OWASP [133] Stored keys are encrypted (with master key wrapping)
 * - OWASP [194] Carefully handle sensitive data (keystore password), wiping char arrays after use
 * - OWASP [199] Resources (File streams) properly closed using try-with-resources
 */
@Component
public class KeyStoreHelper {

    private final KeyStoreLoader loader;
    private final MasterKeyService masterKeyService;
    private final ClientKeyEncryptor encryptor;

    public KeyStoreHelper(KeyStoreLoader loader, MasterKeyService masterKeyService, ClientKeyEncryptor encryptor) {
        this.loader = loader;
        this.masterKeyService = masterKeyService;
        this.encryptor = encryptor;
    }

    public void storeKey(String alias, SecretKey clientKey) {
        KeyStore ks = loader.load();
        SecretKey masterKey = masterKeyService.retrieveMasterKey(ks);
        byte[] encrypted = encryptor.encrypt(clientKey, masterKey);
        storeWrappedKey(ks, alias, encrypted);
        loader.save(ks);
    }

    public SecretKey getClientKey(String alias) {
        KeyStore ks = loader.load();
        SecretKey masterKey = masterKeyService.retrieveMasterKey(ks);
        SecretKey encryptedKey = getKey(ks, alias);
        return encryptor.decrypt(encryptedKey.getEncoded(), masterKey);
    }

    public SecretKey getKey(String alias) {
        return getKey(loader.load(), alias);
    }

    private void storeWrappedKey(final KeyStore ks, final String alias, final byte[] encrypted) {
        final char[] password = System.getenv("KEYSTORE_PASSWORD").toCharArray();

        try {
            final SecretKeySpec encryptedKeySpec = new SecretKeySpec(encrypted, "AES");
            final KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(encryptedKeySpec);
            final KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(password);
            ks.setEntry(alias, entry, protection);
        } catch (final KeyStoreException exception) {
            final ErrorCode errorCode = ErrorCode.SETTING_KEYSTORE_ENTRY_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format("Storing encrypted key under alias: '%s'", alias);
            errorDetailBuilder.withContext(context);
            errorDetailBuilder.withLogMsgFormatted(alias);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private SecretKey getKey(final KeyStore ks, final String alias) {
        final char[] password = System.getenv("KEYSTORE_PASSWORD").toCharArray();

        try {
            return (SecretKey) ks.getKey(alias, password);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_KEY_ACCESS_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format("Retrieving key under alias: '%s' from keystore.", alias);
            errorDetailBuilder.withContext(context);
            errorDetailBuilder.withLogMsgFormatted(alias);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new InternalServerErrorException(errorDetail);
        } finally {
            Arrays.fill(password, '\0');
        }
    }
}
