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

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.errorhandling.exceptions.InternalServerErrorException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class MasterKeyRotationTask {
    private final KeyStoreHelper keyStoreHelper;

    @Scheduled(fixedRate = 86400000)
    public void rotateMasterKey() {
        System.out.println("Start master-key rotation...");

        final KeyStore keystore = keyStoreHelper.loadKeyStore();

        String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
        final char[] passwordChars = keystorePassword.toCharArray();
        keystorePassword = null;

        final SecretKey oldMasterKey;
        try {
            oldMasterKey = (SecretKey) keystore.getKey("master-key", passwordChars);
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_KEY_ACCESS_FAILED.builder()
                    .withContext("While accessing old master key from keystore during master key rotation.")
                    .withLogMsgFormatted("master-key")
                    .withException(exception)
                    .build()
            );
        }

        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException exception) {
            throw new InternalServerErrorException(
                ErrorCode.MASTER_KEY_SECURE_RANDOM_FAILED.builder()
                    .withContext("While generating new master key during master key rotation – SecureRandom initialization.")
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
                    .withContext("While generating new master key during master key rotation – KeyGenerator creation.")
                    .withException(exception)
                    .build()
            );
        }
        
        try {
            keyGen.init(256, secureRandom);
        } catch (final InvalidParameterException exception) {
            throw new InternalServerErrorException(
                ErrorCode.MASTER_KEYGEN_PARAMS_INVALID.builder()
                    .withContext("While initializing KeyGenerator for master key rotation.")
                    .withException(exception)
                    .build()
            );
        }
        
        final SecretKey newMasterKey = keyGen.generateKey();
        
        final Enumeration<String> aliases;
        try {
            aliases = keystore.aliases();
        } catch (final KeyStoreException exception) {
            throw new InternalServerErrorException(
                ErrorCode.KEYSTORE_NOT_INITIALIZED.builder()
                    .withContext("While retrieving aliases from keystore during master key rotation.")
                    .withException(exception)
                    .build()
            );
        }
        
        final List<String> clientKeyAliases = new ArrayList<>();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (!alias.equals("master-key") && !alias.equals("jwt-signing-key")) {
                clientKeyAliases.add(alias);
            }
        }

        for (final String clientAlias : clientKeyAliases) {
            final SecretKeyEntry entry;
            try {
                entry = (SecretKeyEntry) keystore.getEntry(clientAlias, new PasswordProtection(passwordChars));
            } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException exception) {
                throw new InternalServerErrorException(
                    ErrorCode.GETTING_KEYSTORE_ENTRY_FAILED.builder()
                        .withContext(String.format("While getting entry for alias '%s' during master key rotation.", clientAlias))
                        .withException(exception)
                        .build()
                );
            }
        
            final SecretKeySpec wrappedKeySpec = (SecretKeySpec) entry.getSecretKey();
        
            final Cipher unwrapCipher;
            try {
                unwrapCipher = Cipher.getInstance("AES");
            } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
                throw new InternalServerErrorException(
                    ErrorCode.AES_CIPHER_INSTANCE_FAILED.builder()
                        .withContext("While creating AES unwrap cipher during master key rotation.")
                        .withException(exception)
                        .build()
                );
            }
        
            try {
                unwrapCipher.init(Cipher.UNWRAP_MODE, oldMasterKey);
            } catch (final InvalidKeyException | UnsupportedOperationException | InvalidParameterException exception) {
                throw new InternalServerErrorException(
                    ErrorCode.AES_CIPHER_INIT_FAILED.builder()
                        .withContext("While initializing unwrap cipher with old master key.")
                        .withException(exception)
                        .build()
                );
            }
        
            final SecretKey unwrappedClientKey;
            try {
                unwrappedClientKey = (SecretKey) unwrapCipher.unwrap(wrappedKeySpec.getEncoded(), "AES", Cipher.SECRET_KEY);
            } catch (final IllegalStateException | NoSuchAlgorithmException | InvalidKeyException | UnsupportedOperationException exception) {
                throw new InternalServerErrorException(
                    ErrorCode.CLIENT_KEY_UNWRAP_FAILED.builder()
                        .withContext(String.format("While unwrapping client key for alias '%s' during master key rotation.", clientAlias))
                        .withException(exception)
                        .build()
                );
            }
        
            final Cipher wrapCipher;
            try {
                wrapCipher = Cipher.getInstance("AES");
            } catch (final NoSuchAlgorithmException | NoSuchPaddingException exception) {
                throw new InternalServerErrorException(
                    ErrorCode.AES_CIPHER_INSTANCE_FAILED.builder()
                        .withContext("While creating AES wrap cipher during master key rotation.")
                        .withException(exception)
                        .build()
                );
            }
        
            try {
                wrapCipher.init(Cipher.WRAP_MODE, newMasterKey);
            } catch (final InvalidKeyException | UnsupportedOperationException | InvalidParameterException exception) {
                throw new InternalServerErrorException(
                    ErrorCode.AES_CIPHER_INIT_FAILED.builder()
                        .withContext("While initializing wrap cipher with new master key.")
                        .withException(exception)
                        .build()
                );
            }
        
            final byte[] newEncryptedKey;
            try {
                newEncryptedKey = wrapCipher.wrap(unwrappedClientKey);
            } catch (final IllegalStateException | IllegalBlockSizeException | InvalidKeyException | UnsupportedOperationException exception) {
                throw new InternalServerErrorException(
                    ErrorCode.AES_KEY_WRAP_FAILED.builder()
                        .withContext(String.format("While wrapping re-encrypted client key for alias '%s' during master key rotation.", clientAlias))
                        .withException(exception)
                        .build()
                );
            }
        
            final SecretKeySpec newWrappedKeySpec = new SecretKeySpec(newEncryptedKey, "AES");
            final SecretKeyEntry newEntry = new SecretKeyEntry(newWrappedKeySpec);
        
            try {
                keystore.setEntry(clientAlias, newEntry, new PasswordProtection(passwordChars));
            } catch (final KeyStoreException exception) {
                throw new InternalServerErrorException(
                    ErrorCode.SETTING_KEYSTORE_ENTRY_FAILED.builder()
                        .withContext(String.format("While storing rewrapped key for alias '%s' in keystore during master key rotation.", clientAlias))
                        .withException(exception)
                        .build()
                );
            }
        }
        
        final SecretKeyEntry newMasterEntry = new SecretKeyEntry(newMasterKey);
        try {
            keystore.setEntry("master-key", newMasterEntry, new PasswordProtection(passwordChars));
        } catch (final KeyStoreException exception) {
            throw new InternalServerErrorException(
                ErrorCode.SETTING_KEYSTORE_ENTRY_FAILED.builder()
                    .withContext("While storing new master key in keystore after re-wrapping all client keys.")
                    .withException(exception)
                    .build()
            );
        } finally {
           Arrays.fill(passwordChars, '\0'); // OWASP [199]

        }

        keyStoreHelper.saveKeyStore(keystore);
        System.out.println("Master-Key Rotation abgeschlossen und alle Client-Keys re-wrapped.");
    }
}
