package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

/**
 * MasterKeyRotationTask is a scheduled task that rotates the master key in the keystore.
 * It rewraps all client keys with the new master key and updates the keystore accordingly.
 */
@RequiredArgsConstructor
@Component
public class MasterKeyRotationTask {

    private static final Logger LOGGER = LoggerFactory.getLogger(MasterKeyRotationTask.class);
    private static final int KEY_SIZE = 256;

    private final KeyStoreLoader keyStoreLoader;
    private final MasterKeyService masterKeyService;
    private final ErrorHandler errorHandler;

    /**
     * Scheduled method that runs every 24 hours to rotate the master key.
     * It generates a new master key, rewraps all client keys, and updates the keystore.
     */
    @Scheduled(fixedRate = 86400000L)
    public final void rotateMasterKey() {
        LOGGER.info("Starting scheduled master key rotation process");

        final KeyStore keystore = this.keyStoreLoader.load();
        final char[] passwordChars = this.getPassword();

        final SecretKey oldMasterKey = this.masterKeyService.retrieveMasterKey(keystore);
        final SecretKey newMasterKey = this.generateNewMasterKey();

        final List<String> clientKeyAliases = this.getClientKeyAliases(keystore);
        this.rewrapClientKeys(keystore, oldMasterKey, newMasterKey, clientKeyAliases, passwordChars);

        this.storeNewMasterKey(keystore, newMasterKey, passwordChars);
        this.keyStoreLoader.save(keystore);

        LOGGER.info("Master key rotation process completed successfully");
    }

    /**
     * Retrieves the keystore password from the environment variable.
     * This method is used to access the keystore securely.
     *
     * @return the keystore password as a char array
     */
    private char[] getPassword() {
        final String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        return keystorePassword.toCharArray();
    }

    /**
     * Generates a new master key using a secure random generator.
     *
     * @return the newly generated SecretKey
     */
    private SecretKey generateNewMasterKey() {
        try {
            final SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(KEY_SIZE, secureRandom);
            return keyGen.generateKey();
        } catch (final NoSuchAlgorithmException | InvalidParameterException exception) {
            throw this.errorHandler.handleError(
                ErrorCode.MASTER_KEYGEN_INIT_FAILED,
                "While generating new master key.",
                exception
            );
        }
    }

    /**
     * Retrieves all client key aliases from the KeyStore, excluding the master key and JWT signing key.
     *
     * @param keystore the KeyStore instance from which to retrieve client key aliases
     * @return a list of client key aliases
     */
    private List<String> getClientKeyAliases(final KeyStore keystore) {
        try {
            final Enumeration<String> aliases = keystore.aliases();
            final List<String> clientKeyAliases = new ArrayList<>();
            while (aliases.hasMoreElements()) {
                final String alias = aliases.nextElement();
                if (!"master-key".equals(alias) && !"jwt-signing-key".equals(alias)) {
                    clientKeyAliases.add(alias);
                }
            }
            return clientKeyAliases;
        } catch (final KeyStoreException exception) {
            throw this.errorHandler.handleError(
                ErrorCode.KEYSTORE_NOT_INITIALIZED,
                "While retrieving client key aliases from keystore.",
                exception
            );
        }
    }

    /**
     * Rewraps all client keys with the new master key and updates the KeyStore.
     *
     * @param keystore the KeyStore instance containing the client keys
     * @param oldMasterKey the old master key used to unwrap client keys
     * @param newMasterKey the new master key used to wrap client keys
     * @param clientKeyAliases a list of client key aliases to rewrap
     * @param passwordChars the password characters used to access the KeyStore
     */
    private void rewrapClientKeys(final KeyStore keystore, final SecretKey oldMasterKey, final SecretKey newMasterKey, final List<String> clientKeyAliases, final char[] passwordChars) {
        for (final String clientAlias : clientKeyAliases) {
            LOGGER.debug("Rewrapping client key: {}", clientAlias);

            final SecretKey unwrappedClientKey = this.unwrapClientKey(keystore, oldMasterKey, clientAlias, passwordChars);
            final byte[] newEncryptedKey = this.wrapClientKey(newMasterKey, unwrappedClientKey);

            this.storeClientKey(keystore, clientAlias, newEncryptedKey, passwordChars);
        }
    }

    /**
     * Unwraps the client key using the old master key.
     *
     * @param keystore the KeyStore instance containing the client key
     * @param oldMasterKey the old master key used for unwrapping
     * @param clientAlias the alias of the client key to unwrap
     * @param passwordChars the password characters used to access the KeyStore
     * @return the unwrapped SecretKey
     */
    private SecretKey unwrapClientKey(final KeyStore keystore, final SecretKey oldMasterKey, final String clientAlias, final char[] passwordChars) {
        try {
            final SecretKeyEntry entry = (SecretKeyEntry) keystore.getEntry(clientAlias, new PasswordProtection(passwordChars));
            final SecretKeySpec wrappedKeySpec = (SecretKeySpec) entry.getSecretKey();

            final Cipher unwrapCipher = Cipher.getInstance("AES");
            unwrapCipher.init(Cipher.UNWRAP_MODE, oldMasterKey);

            final byte[] encoded = wrappedKeySpec.getEncoded();
            return (SecretKey) unwrapCipher.unwrap(encoded, "AES", Cipher.SECRET_KEY);
        } catch (final NoSuchPaddingException | InvalidKeyException | NoSuchAlgorithmException |
                       UnrecoverableEntryException | KeyStoreException exception) {
            final String context = String.format("While unwrapping client key for alias: %s", clientAlias);
            throw this.errorHandler.handleError(
                ErrorCode.CLIENT_KEY_UNWRAP_FAILED,
                context,
                exception
            );
        }
    }

    /**
     * Wraps the unwrapped client key with the new master key.
     *
     * @param newMasterKey the new master key used for wrapping
     * @param unwrappedClientKey the unwrapped client key to be wrapped
     * @return the wrapped client key as a byte array
     */
    private byte[] wrapClientKey(final SecretKey newMasterKey, final SecretKey unwrappedClientKey) {
        try {
            final Cipher wrapCipher = Cipher.getInstance("AES");
            wrapCipher.init(Cipher.WRAP_MODE, newMasterKey);
            return wrapCipher.wrap(unwrappedClientKey);
        } catch (final InvalidKeyException | IllegalBlockSizeException | NoSuchAlgorithmException |
                       NoSuchPaddingException exception) {
            throw this.errorHandler.handleError(
                ErrorCode.AES_KEY_WRAP_FAILED,
        "While wrapping client key with new master key using AES cipher.",
                exception
            );
        }
    }

    /**
     * Stores the rewrapped client key back into the KeyStore.
     *
     * @param keystore the KeyStore instance where the client key will be stored
     * @param clientAlias the alias under which the client key will be stored
     * @param newEncryptedKey the rewrapped client key as a byte array
     * @param passwordChars the password characters used to access the KeyStore
     */
    private void storeClientKey(final KeyStore keystore, final String clientAlias, final byte[] newEncryptedKey, final char[] passwordChars) {
        try {
            final SecretKeySpec newWrappedKeySpec = new SecretKeySpec(newEncryptedKey, "AES");
            final SecretKeyEntry newEntry = new SecretKeyEntry(newWrappedKeySpec);
            keystore.setEntry(clientAlias, newEntry, new PasswordProtection(passwordChars));
            LOGGER.info("Successfully rewrapped and stored client key '{}'", clientAlias);
        } catch (final KeyStoreException exception) {
            final String context = String.format("While storing rewrapped key for client alias: %s", clientAlias);
            throw this.errorHandler.handleError(
                ErrorCode.SETTING_KEYSTORE_ENTRY_FAILED,
                context,
                exception
            );
        }
    }

    /**
     * Stores the new master key in the KeyStore.
     *
     * @param keystore the KeyStore instance where the new master key will be stored
     * @param newMasterKey the newly generated master key to be stored
     * @param passwordChars the password characters used to access the KeyStore
     */
    private void storeNewMasterKey(final KeyStore keystore, final SecretKey newMasterKey, final char[] passwordChars) {
        try {
            final SecretKeyEntry newMasterEntry = new SecretKeyEntry(newMasterKey);
            keystore.setEntry("master-key", newMasterEntry, new PasswordProtection(passwordChars));
            LOGGER.info("New master key successfully stored in keystore");
        } catch (final KeyStoreException exception) {
            throw this.errorHandler.handleError(
                ErrorCode.SETTING_KEYSTORE_ENTRY_FAILED,
        "While storing new master key in keystore.",
                exception
            );
        } finally {
            Arrays.fill(passwordChars, '\0'); // OWASP [199]
        }
    }
}
