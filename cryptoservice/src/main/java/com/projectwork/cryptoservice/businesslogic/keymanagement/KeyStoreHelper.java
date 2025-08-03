package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;

/**
 * KeyStoreHelper is a utility class for managing cryptographic keys in a secure manner.
 *
 * SCPs:
 * - [114] Logging controls should support both success and failure of specified security events
 */
@Component
@RequiredArgsConstructor
public class KeyStoreHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreHelper.class);

    private final KeyStoreLoader loader;
    private final MasterKeyService masterKeyService;
    private final ClientKeyEncryptor encryptor;
    private final ErrorHandler errorHandler;

    /**
     * Stores a key in the master-keystore under the specified keyAlias.
     *
     * @param keyAlias      the keyAlias under which the key will be stored
     * @param key  the client key to be stored
     *
     * SCP106 (Key storage) -> setKeystoreEntry
     */
    public final void storeKey(final String keyAlias, final byte[] key, final String keystorePath, final String keystorePassword) {
        LOGGER.debug("Storing key...");

        final KeyStore keystore = this.loader.load(keystorePath, keystorePassword);

        this.setKeystoreEntry(keystore, keyAlias, key, keystorePassword);
        this.loader.save(keystore, keystorePath, keystorePassword);

        LOGGER.info("Key stored and saved successfully in keystore.");
    }

    /**
     * Stores a client key in the keystore under the specified keyAlias.
     *
     * @param keyAlias      the keyAlias under which the key will be stored
     * @param clientKey  the client key to be stored
     * @param keystorePath the path to the keystore
     * @param keystorePassword the password for the keystore
     *
     * SCP106 (Key storage) -> setKeystoreEntry
     */
    public final void storeClientKey(final String keyAlias, final SecretKey clientKey, final String keystorePath, final String keystorePassword) {
        LOGGER.debug("Storing client key for current client with specific keyAlias");

        final KeyStore keystore = this.loader.load(keystorePath, keystorePassword);
        final SecretKey masterKey = this.masterKeyService.retrieveMasterKey();
        final byte[] encryptedKey = this.encryptor.encrypt(clientKey, masterKey);

        this.setKeystoreEntry(keystore, keyAlias, encryptedKey, keystorePassword);
        this.loader.save(keystore, keystorePath, keystorePassword);

        LOGGER.info("Key stored and saved successfully in keystore.");
    }

    /**
     * Retrieves and decrypts the client key stored under the specified alias.
     *
     * @param alias the alias of the key to retrieve
     * @return the decrypted client key
     */
    public final SecretKey getClientKey(final String alias, final String keystorePath, final String keystorePassword) {
        LOGGER.debug("Retrieving and decrypting client key.");

        final KeyStore keystore = this.loader.load(keystorePath, keystorePassword);
        final SecretKey masterKey = this.masterKeyService.retrieveMasterKey();
        final SecretKey encryptedKey = this.getKey(keystore, alias, keystorePassword);
        final byte[] encoded = encryptedKey.getEncoded();
        final SecretKey decrypted = this.encryptor.decrypt(encoded, masterKey);

        LOGGER.info("Client key successfully retrieved and decrypted.");
        return decrypted;
    }

    /**
     * Retrieves the raw key stored under the specified alias without decryption.
     *
     * @param alias the alias of the key to retrieve
     * @return the raw SecretKey associated with the alias
     */
    public final SecretKey getKey(final String alias, final String keystorePath, final String keystorePassword) {
        LOGGER.debug("Retrieving key (raw) for specific alias.");
        final KeyStore keyStore = this.loader.load(keystorePath, keystorePassword);
        final SecretKey key = this.getKey(keyStore, alias, keystorePassword);
        LOGGER.info("Key successfully retrieved.");
        return key;
    }

    /**
     * Stores a wrapped key in the KeyStore under the specified alias.
     *
     * @param ks        the KeyStore instance where the key will be stored
     * @param alias     the alias under which the key will be stored
     * @param key the key key to be stored
     *
     * SCP106 (Key storage)
     */
    private void setKeystoreEntry(final KeyStore ks, final String alias, final byte[] key, final String keystorePassword) {
        final char[] password = keystorePassword.toCharArray();

        try {
            LOGGER.debug("Storing wrapped key in keystore.");
            final SecretKeySpec encryptedKeySpec = new SecretKeySpec(key, "AES");
            final SecretKeyEntry entry = new SecretKeyEntry(encryptedKeySpec);
            final ProtectionParameter protection = new PasswordProtection(password);
            ks.setEntry(alias, entry, protection);
            LOGGER.debug("Wrapped key stored successfully.");
        } catch (final KeyStoreException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.SETTING_KEYSTORE_ENTRY_FAILED,
                    alias,
                    "While storing key.",
                    exception
            );
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /**
     * Retrieves a SecretKey from the KeyStore using the specified alias.
     * It uses the keystore password from the environment variable "KEYSTORE_PASSWORD".
     *
     * @param ks    the KeyStore instance to retrieve the key from
     * @param alias the alias of the key to retrieve
     * @return the SecretKey associated with the specified alias
     */
    private SecretKey getKey(final KeyStore ks, final String alias, final String keystorePassword) {
        final char[] password = keystorePassword.toCharArray();

        try {
            LOGGER.debug("Accessing KeyStore entry.");
            return (SecretKey) ks.getKey(alias, password);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.KEYSTORE_KEY_ACCESS_FAILED,
                    alias,
                    "While retrieving key.",
                    exception
            );
        } finally {
            Arrays.fill(password, '\0');
            LOGGER.debug("KeyStore entry accessed successfully.");
        }
    }
}
