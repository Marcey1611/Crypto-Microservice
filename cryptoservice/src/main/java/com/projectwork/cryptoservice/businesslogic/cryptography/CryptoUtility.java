package com.projectwork.cryptoservice.businesslogic.cryptography;

import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for cryptographic operations, specifically AES-GCM encryption.
 *
 * SCPs:
 * - [101] All cryptographic functions used to protect secrets from the application user must be implemented on a trusted system (e.g., the server)
 * - [129] Log cryptographic module failures
 */
@Service
@RequiredArgsConstructor
public class CryptoUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoUtility.class);
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;

    private final ErrorHandler errorHandler;

    /**
     * Creates a Cipher instance for AES-GCM encryption.
     * @return The Cipher instance.
     *
     * SCP103
     */
    public final Cipher createCipher() {
        try {
            final Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            LOGGER.debug("Cipher instance created with algorithm.");
            return cipher;
        } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.AES_CIPHER_INSTANCE_FAILED,
                    "While creating Cipher instance for AES encryption.",
                    exception
            );
        }
    }

    /**
     * Creates a GCMParameterSpec for encryption.
     * @param iv The initialization vector.
     * @return The GCMParameterSpec instance.
     *
     * SCP103
     */
    public final GCMParameterSpec createGCMParameterSpec(final byte[] iv) {
        try {
            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            LOGGER.debug("GCMParameterSpec created.");
            return gcmParameterSpec;
        } catch (final IllegalArgumentException exception) {
            throw this.errorHandler.handleClientError(
                    ErrorCode.INVALID_GCM_PARAMETERS,
                    exception,
                    "While creating GCMParameterSpec for AES encryption."
            );
        }
    }

    /**
     * Initializes the Cipher for decryption mode.
     * @param cipher The Cipher instance.
     * @param clientKey The secret key.
     * @param gcmParameterSpec The GCM parameters.
     *
     * SCP103
     */
    public final void initCipher(final Cipher cipher, final SecretKey clientKey, final GCMParameterSpec gcmParameterSpec, int opmode) {
        try {
            cipher.init(opmode, clientKey, gcmParameterSpec);
            LOGGER.debug("Cipher initialized for decryption mode.");
        } catch (final InvalidKeyException | InvalidAlgorithmParameterException | InvalidParameterException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.AES_CIPHER_INIT_FAILED,
                    "While initializing Cipher for decryption with client key and GCM parameters.",
                    exception
            );
        }
    }
}
