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
     * Stores a client key in the keystore under the specified keyAlias.
     *
     * @param keyAlias      the keyAlias under which the key will be stored
     * @param clientKey  the client key to be stored
     */
    public final void storeKey(final String keyAlias, final SecretKey clientKey, final String keystorePath, final String keystorePassword) {
        LOGGER.debug("Storing key for keyAlias '{}'", keyAlias);

        final KeyStore keystore = this.loader.load(keystorePath, keystorePassword);
        final SecretKey masterKey = this.masterKeyService.retrieveMasterKey();
        final byte[] encryptedKey = this.encryptor.encrypt(clientKey, masterKey);

        this.storeWrappedKey(keystore, keyAlias, encryptedKey, keystorePassword);
        this.loader.save(keystore, keystorePath, keystorePassword);

        LOGGER.info("Key stored and saved in keystore for keyAlias '{}'", keyAlias);
    }

    /**
     * Retrieves and decrypts the client key stored under the specified alias.
     *
     * @param alias the alias of the key to retrieve
     * @return the decrypted client key
     */
    public final SecretKey getClientKey(final String alias, final String keystorePath, final String keystorePassword) {
        LOGGER.debug("Retrieving and decrypting client key for alias '{}'", alias);

        final KeyStore keystore = this.loader.load(keystorePath, keystorePassword);
        final SecretKey masterKey = this.masterKeyService.retrieveMasterKey();
        final SecretKey encryptedKey = this.getKey(keystore, alias, keystorePassword);
        final byte[] encoded = encryptedKey.getEncoded();
        final SecretKey decrypted = this.encryptor.decrypt(encoded, masterKey);

        LOGGER.info("Client key successfully retrieved and decrypted for alias '{}'", alias);
        return decrypted;
    }

    /**
     * Retrieves the raw key stored under the specified alias without decryption.
     *
     * @param alias the alias of the key to retrieve
     * @return the raw SecretKey associated with the alias
     */
    public final SecretKey getKey(final String alias, final String keystorePath, final String keystorePassword) {
        LOGGER.debug("Retrieving key (raw) for alias '{}'", alias);
        final KeyStore keyStore = this.loader.load(keystorePath, keystorePassword);
        final SecretKey key = this.getKey(keyStore, alias, keystorePassword);
        LOGGER.info("Key successfully retrieved for alias '{}'", alias);
        return key;
    }

    /**
     * Stores a wrapped key in the KeyStore under the specified alias.
     *
     * @param ks        the KeyStore instance where the key will be stored
     * @param alias     the alias under which the key will be stored
     * @param encrypted the encrypted key to be stored
     */
    private void storeWrappedKey(final KeyStore ks, final String alias, final byte[] encrypted, final String keystorePassword) {
        final char[] password = keystorePassword.toCharArray();

        try {
            LOGGER.debug("Storing wrapped key in keystore under alias '{}'", alias);
            final SecretKeySpec encryptedKeySpec = new SecretKeySpec(encrypted, "AES");
            final SecretKeyEntry entry = new SecretKeyEntry(encryptedKeySpec);
            final ProtectionParameter protection = new PasswordProtection(password);
            ks.setEntry(alias, entry, protection);
            LOGGER.debug("Wrapped key stored successfully under alias '{}'", alias);
        } catch (final KeyStoreException exception) {
            final String context = String.format("Storing encrypted key under alias: '%s'", alias);
            throw this.errorHandler.handleError(
                    ErrorCode.SETTING_KEYSTORE_ENTRY_FAILED,
                    alias,
                    context,
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
            LOGGER.debug("Accessing KeyStore entry for alias '{}'", alias);
            return (SecretKey) ks.getKey(alias, password);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            final String context = String.format("Retrieving key under alias: '%s' from keystore.", alias);
            throw this.errorHandler.handleError(
                    ErrorCode.KEYSTORE_KEY_ACCESS_FAILED,
                    alias,
                    context,
                    exception
            );
        } finally {
            Arrays.fill(password, '\0');
        }
    }
}
