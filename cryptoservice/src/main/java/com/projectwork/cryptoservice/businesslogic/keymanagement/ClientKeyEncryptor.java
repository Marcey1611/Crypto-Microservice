package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;

/**
 * ClientKeyEncryptor is a utility class for encrypting and decrypting client keys using a master key.
 * It uses AES wrapping for secure key management.
 */
@Component
@RequiredArgsConstructor
public class ClientKeyEncryptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientKeyEncryptor.class);

    private final ErrorHandler errorHandler;

    /**
     * Encrypts a client key using the provided master key.
     *
     * @param clientKey the client key to encrypt
     * @param masterKey the master key used for encryption
     * @return the encrypted client key as a byte array
     */
    public final byte[] encrypt(final SecretKey clientKey, final SecretKey masterKey) {
        LOGGER.debug("Encrypting client key with master key (AES wrap)");

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
            throw this.errorHandler.handleError(
                    ErrorCode.AES_CIPHER_INSTANCE_FAILED,
                    "Preparing AES cipher for encryption.",
                    exception
            );
        }

        try {
            cipher.init(Cipher.WRAP_MODE, masterKey);
            final byte[] wrapped = cipher.wrap(clientKey);
            LOGGER.info("Client key successfully encrypted with master key");
            return wrapped;
        } catch (final InvalidKeyException | IllegalBlockSizeException | UnsupportedOperationException | InvalidParameterException exception) {
            throw this.errorHandler.handleError(
                    ErrorCode.AES_KEY_WRAP_FAILED,
                    "Wrapping client key with master key using AES cipher.",
                    exception
            );
        }
    }

    /**
     * Decrypts an encrypted client key using the provided master key.
     *
     * @param encryptedKey the encrypted client key as a byte array
     * @param masterKey    the master key used for decryption
     * @return the decrypted client key as a SecretKey
     */
    public final SecretKey decrypt(final byte[] encryptedKey, final SecretKey masterKey) {
        LOGGER.debug("Decrypting client key with master key (AES unwrap)");

        final Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
            throw this.errorHandler.handleError(
                    ErrorCode.AES_CIPHER_INSTANCE_FAILED,
                    "Preparing AES cipher for decryption.",
                    exception
            );
        }

        try {
            cipher.init(Cipher.UNWRAP_MODE, masterKey);
            final SecretKey unwrapped = (SecretKey) cipher.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);
            LOGGER.info("Client key successfully decrypted with master key");
            return unwrapped;
        } catch (final InvalidKeyException | NoSuchAlgorithmException | UnsupportedOperationException | InvalidParameterException exception) {
            throw this.errorHandler.handleError(
                    ErrorCode.CLIENT_KEY_UNWRAP_FAILED,
                    "Unwrapping encrypted client key using AES cipher and master key.",
                    exception
            );
        }
    }
}
