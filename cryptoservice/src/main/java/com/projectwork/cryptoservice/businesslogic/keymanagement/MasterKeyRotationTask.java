package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

import lombok.RequiredArgsConstructor;

//TODO refactoring too complex (methods)
/**
 * MasterKeyRotationTask is a scheduled task that rotates the master key in the keystore.
 * It re-wraps all client keys with the new master key and updates the keystore accordingly.
 * SecureCodingPractices:
 * - OWASP [101] Crypto operations (key gen) on trusted server
 * - OWASP [104] Secure Random for all key generations
 * - OWASP [106] Key management initialization (ensures master and signing keys)
 */
@RequiredArgsConstructor
@Component
public class MasterKeyRotationTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(MasterKeyRotationTask.class);
    private static final int KEY_SIZE = 256;

    private final KeyStoreLoader keyStoreLoader;

    @Scheduled(fixedRate = 86400000L)
    public final void rotateMasterKey() {

        LOGGER.info("Starting scheduled master key rotation process");

        final KeyStore keystore = this.keyStoreLoader.load();
        final String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();

        LOGGER.debug("Retrieving current master key from keystore");

        final SecretKey oldMasterKey;
        try {
            oldMasterKey = (SecretKey) keystore.getKey("master-key", passwordChars);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_KEY_ACCESS_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While accessing old master key from keystore during master key rotation.");
            errorDetailBuilder.withLogMsgFormatted("master-key");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        LOGGER.debug("Generating new AES master key using SecureRandom");

        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException exception) {
            final ErrorCode errorCode = ErrorCode.MASTER_KEY_SECURE_RANDOM_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While generating new master key during master key rotation – SecureRandom initialization.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        final KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (final NoSuchAlgorithmException exception) {
            final ErrorCode errorCode = ErrorCode.MASTER_KEYGEN_INIT_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While generating new master key during master key rotation – KeyGenerator creation.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        try {
            keyGen.init(KEY_SIZE, secureRandom);
        } catch (final InvalidParameterException exception) {
            final ErrorCode errorCode = ErrorCode.MASTER_KEYGEN_PARAMS_INVALID;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While initializing KeyGenerator for master key rotation.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        final SecretKey newMasterKey = keyGen.generateKey();
        LOGGER.info("New master key successfully generated");

        LOGGER.debug("Fetching client key aliases from keystore");

        final Enumeration<String> aliases;
        try {
            aliases = keystore.aliases();
        } catch (final KeyStoreException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_NOT_INITIALIZED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While retrieving aliases from keystore during master key rotation.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        }

        final List<String> clientKeyAliases = new ArrayList<>();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (!"master-key".equals(alias) && !"jwt-signing-key".equals(alias)) {
                clientKeyAliases.add(alias);
            }
        }

        LOGGER.info("Found {} client keys to rewrap", clientKeyAliases.size());

        for (final String clientAlias : clientKeyAliases) {
            LOGGER.debug("Rewrapping client key: {}", clientAlias);

            final SecretKeyEntry entry;
            try {
                entry = (SecretKeyEntry) keystore.getEntry(clientAlias, new PasswordProtection(passwordChars));
            } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException exception) {
                final ErrorCode errorCode = ErrorCode.GETTING_KEYSTORE_ENTRY_FAILED;
                final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
                errorDetailBuilder.withContext("While getting entry for alias '" + clientAlias + "' during master key rotation.");
                errorDetailBuilder.withException(exception);
                final ErrorDetail errorDetail = errorDetailBuilder.build();
                errorDetail.logErrorWithException();
                throw new InternalServerErrorException(errorDetail);
            }

            final SecretKeySpec wrappedKeySpec = (SecretKeySpec) entry.getSecretKey();

            final Cipher unwrapCipher;
            try {
                unwrapCipher = Cipher.getInstance("AES");
            } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
                final ErrorCode errorCode = ErrorCode.AES_CIPHER_INSTANCE_FAILED;
                final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
                errorDetailBuilder.withContext("While creating AES unwrap cipher during master key rotation.");
                errorDetailBuilder.withException(exception);
                final ErrorDetail errorDetail = errorDetailBuilder.build();
                errorDetail.logErrorWithException();
                throw new InternalServerErrorException(errorDetail);
            }

            try {
                unwrapCipher.init(Cipher.UNWRAP_MODE, oldMasterKey);
            } catch (final InvalidKeyException | UnsupportedOperationException | InvalidParameterException exception) {
                final ErrorCode errorCode = ErrorCode.AES_CIPHER_INIT_FAILED;
                final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
                errorDetailBuilder.withContext("While initializing unwrap cipher with old master key.");
                errorDetailBuilder.withException(exception);
                final ErrorDetail errorDetail = errorDetailBuilder.build();
                errorDetail.logErrorWithException();
                throw new InternalServerErrorException(errorDetail);
            }

            final SecretKey unwrappedClientKey;
            try {
                final byte[] wrappedKeySpecEncoded = wrappedKeySpec.getEncoded();
                unwrappedClientKey = (SecretKey) unwrapCipher.unwrap(wrappedKeySpecEncoded, "AES", Cipher.SECRET_KEY);
            } catch (final IllegalStateException | NoSuchAlgorithmException | InvalidKeyException | UnsupportedOperationException exception) {
                final ErrorCode errorCode = ErrorCode.CLIENT_KEY_UNWRAP_FAILED;
                final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
                errorDetailBuilder.withContext("While unwrapping client key for alias '" + clientAlias + "' during master key rotation.");
                errorDetailBuilder.withException(exception);
                final ErrorDetail errorDetail = errorDetailBuilder.build();
                errorDetail.logErrorWithException();
                throw new InternalServerErrorException(errorDetail);
            }

            final Cipher wrapCipher;
            try {
                wrapCipher = Cipher.getInstance("AES");
            } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
                final ErrorCode errorCode = ErrorCode.AES_CIPHER_INSTANCE_FAILED;
                final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
                errorDetailBuilder.withContext("While creating AES wrap cipher during master key rotation.");
                errorDetailBuilder.withException(exception);
                final ErrorDetail errorDetail = errorDetailBuilder.build();
                errorDetail.logErrorWithException();
                throw new InternalServerErrorException(errorDetail);
            }

            try {
                wrapCipher.init(Cipher.WRAP_MODE, newMasterKey);
            } catch (final InvalidKeyException | UnsupportedOperationException | InvalidParameterException exception) {
                final ErrorCode errorCode = ErrorCode.AES_CIPHER_INIT_FAILED;
                final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
                errorDetailBuilder.withContext("While initializing wrap cipher with new master key.");
                errorDetailBuilder.withException(exception);
                final ErrorDetail errorDetail = errorDetailBuilder.build();
                errorDetail.logErrorWithException();
                throw new InternalServerErrorException(errorDetail);
            }

            final byte[] newEncryptedKey;
            try {
                newEncryptedKey = wrapCipher.wrap(unwrappedClientKey);
            } catch (final IllegalStateException | IllegalBlockSizeException | InvalidKeyException | UnsupportedOperationException exception) {
                final ErrorCode errorCode = ErrorCode.AES_KEY_WRAP_FAILED;
                final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
                errorDetailBuilder.withContext("While wrapping re-encrypted client key for alias '" + clientAlias + "' during master key rotation.");
                errorDetailBuilder.withException(exception);
                final ErrorDetail errorDetail = errorDetailBuilder.build();
                errorDetail.logErrorWithException();
                throw new InternalServerErrorException(errorDetail);
            }

            final SecretKeySpec newWrappedKeySpec = new SecretKeySpec(newEncryptedKey, "AES");
            final SecretKeyEntry newEntry = new SecretKeyEntry(newWrappedKeySpec);

            try {
                keystore.setEntry(clientAlias, newEntry, new PasswordProtection(passwordChars));
                LOGGER.info("Successfully rewrapped and stored client key '{}'", clientAlias);
            } catch (final KeyStoreException exception) {
                final ErrorCode errorCode = ErrorCode.SETTING_KEYSTORE_ENTRY_FAILED;
                final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
                errorDetailBuilder.withContext("While storing rewrapped key for alias '" + clientAlias + "' in keystore during master key rotation.");
                errorDetailBuilder.withException(exception);
                final ErrorDetail errorDetail = errorDetailBuilder.build();
                errorDetail.logErrorWithException();
                throw new InternalServerErrorException(errorDetail);
            }
        }

        final SecretKeyEntry newMasterEntry = new SecretKeyEntry(newMasterKey);
        try {
            keystore.setEntry("master-key", newMasterEntry, new PasswordProtection(passwordChars));
            LOGGER.info("New master key successfully stored in keystore");
        } catch (final KeyStoreException exception) {
            final ErrorCode errorCode = ErrorCode.SETTING_KEYSTORE_ENTRY_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withContext("While storing new master key in keystore after re-wrapping all client keys.");
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [199]
        }

        this.keyStoreLoader.save(keystore);
        LOGGER.info("Master key rotation process completed successfully");
    }
}
