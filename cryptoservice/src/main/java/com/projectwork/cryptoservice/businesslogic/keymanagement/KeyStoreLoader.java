package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;

/**
 * KeyStoreLoader is responsible for loading and saving the keystore from/to a file.
 * It uses environment variables to determine the keystore path and password.
 *
 * SCPs:
 * - [114] Logging controls should support both success and failure of specified security events
 */
@Component
@RequiredArgsConstructor
public class KeyStoreLoader {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreLoader.class);

    private final ErrorHandler errorHandler;

    /**
     * Loads the keystore from the specified file path.
     *
     * @return the loaded KeyStore instance
     * @throws InternalServerErrorException if there is an error loading the keystore
     */
    public KeyStore load(final String path, final String password) {
        final File keystoreFile = new File(path);
        final char[] passwordChars = password.toCharArray();
        final String absolutePath = keystoreFile.getAbsolutePath();

        LOGGER.debug("Attempting to load keystore.");

        try (final FileInputStream fis = new FileInputStream(absolutePath)) {
            final KeyStore keystore = KeyStore.getInstance("PKCS12");
            try {
                keystore.load(fis, passwordChars);
                LOGGER.info("Keystore successfully loaded.");
            } catch (final IOException | NoSuchAlgorithmException | CertificateException exception) {
                throw this.errorHandler.handleBusinessError(
                        ErrorCode.KEYSTORE_LOADING_FAILED,
                        "While loading keystore data from file into memory.",
                        exception
                );
            }
            return keystore;
        } catch (final IOException | SecurityException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.KEYSTORE_FILE_READ_FAILED,
                    "While opening keystore file for reading.",
                    exception
            );
        } catch (final KeyStoreException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.KEYSTORE_TYPE_UNSUPPORTED,
                    "While creating keystore instance for loading.",
                    exception
            );
        } finally {
            Arrays.fill(passwordChars, '\0');
            LOGGER.debug("Successfully loaded keystore.");
        }
    }

    /**
     * Saves the provided keystore to the specified file path.
     *
     * @param keystore the KeyStore instance to save
     * @throws InternalServerErrorException if there is an error saving the keystore
     */
    public void save(final KeyStore keystore, final String path, final String password) {
        final File keystoreFile = new File(path);
        final char[] passwordChars = password.toCharArray();
        final String absolutePath = keystoreFile.getAbsolutePath();

        LOGGER.debug("Attempting to save keystore.");

        try (final FileOutputStream fos = new FileOutputStream(absolutePath)) {
            try {
                keystore.store(fos, passwordChars);
                LOGGER.info("Keystore successfully saved to '{}'", absolutePath);
            } catch (final KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException exception) {
                throw this.errorHandler.handleBusinessError(
                        ErrorCode.KEYSTORE_SAVE_FAILED,
                        "While storing keystore data to file.",
                        exception
                );
            }
        } catch (final IOException | SecurityException exception) {
            throw this.errorHandler.handleBusinessError(
                    ErrorCode.KEYSTORE_FILE_WRITE_FAILED,
                    "While opening keystore file for writing.",
                    exception
            );
        } finally {
            Arrays.fill(passwordChars, '\0');
            LOGGER.debug("Successfully saved keystore.");
        }
    }
}

