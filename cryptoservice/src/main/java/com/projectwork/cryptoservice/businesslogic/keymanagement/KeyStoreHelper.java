package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
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

    /**
     * Stores a client key in the keystore under the specified alias.
     *
     * @param alias      the alias under which the key will be stored
     * @param clientKey  the client key to be stored
     */
    public final void storeKey(final String alias, final SecretKey clientKey) {
        LOGGER.debug("Storing key for alias '{}'", alias);

        final KeyStore ks = this.loader.load();
        final SecretKey masterKey = this.masterKeyService.retrieveMasterKey(ks);
        final byte[] encrypted = this.encryptor.encrypt(clientKey, masterKey);

        this.storeWrappedKey(ks, alias, encrypted);
        this.loader.save(ks);

        LOGGER.info("Key stored and saved in keystore for alias '{}'", alias);
    }

    /**
     * Retrieves and decrypts the client key stored under the specified alias.
     *
     * @param alias the alias of the key to retrieve
     * @return the decrypted client key
     */
    public final SecretKey getClientKey(final String alias) {
        LOGGER.debug("Retrieving and decrypting client key for alias '{}'", alias);

        final KeyStore ks = this.loader.load();
        final SecretKey masterKey = this.masterKeyService.retrieveMasterKey(ks);
        final SecretKey encryptedKey = this.getKey(ks, alias);
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
    public final SecretKey getKey(final String alias) {
        LOGGER.debug("Retrieving key (raw) for alias '{}'", alias);
        final KeyStore keyStore = this.loader.load();
        final SecretKey key = this.getKey(keyStore, alias);
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
    private void storeWrappedKey(final KeyStore ks, final String alias, final byte[] encrypted) {
        final String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] password = keystorePassword.toCharArray();

        try {
            LOGGER.debug("Storing wrapped key in keystore under alias '{}'", alias);
            final SecretKeySpec encryptedKeySpec = new SecretKeySpec(encrypted, "AES");
            final SecretKeyEntry entry = new SecretKeyEntry(encryptedKeySpec);
            final ProtectionParameter protection = new PasswordProtection(password);
            ks.setEntry(alias, entry, protection);
            LOGGER.debug("Wrapped key stored successfully under alias '{}'", alias);
        } catch (final KeyStoreException exception) {
            final ErrorCode errorCode = ErrorCode.SETTING_KEYSTORE_ENTRY_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format("Storing encrypted key under alias: '%s'", alias);
            errorDetailBuilder.withContext(context);
            errorDetailBuilder.withLogMsgFormatted(alias);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
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
    private SecretKey getKey(final KeyStore ks, final String alias) {
        final String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] password = keystorePassword.toCharArray();

        try {
            LOGGER.debug("Accessing KeyStore entry for alias '{}'", alias);
            return (SecretKey) ks.getKey(alias, password);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            final ErrorCode errorCode = ErrorCode.KEYSTORE_KEY_ACCESS_FAILED;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            final String context = String.format("Retrieving key under alias: '%s' from keystore.", alias);
            errorDetailBuilder.withContext(context);
            errorDetailBuilder.withLogMsgFormatted(alias);
            errorDetailBuilder.withException(exception);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            errorDetail.logErrorWithException();
            throw new InternalServerErrorException(errorDetail);
        } finally {
            Arrays.fill(password, '\0');
        }
    }
}
