package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class MasterKeyRotationTask {
    private final KeyStoreHelper keyStoreHelper;

    @Scheduled(fixedRate = 86400000)
    public void rotateMasterKey() {
        try {
            System.out.println("Start master-key rotation...");

            final KeyStore keystore = keyStoreHelper.loadKeyStore();

            String keystorePassword = System.getenv("KEYSTORE_PASSWORD");
            final char[] passwordChars = keystorePassword.toCharArray();
            keystorePassword = null;
            final SecretKey oldMasterKey = (SecretKey) keystore.getKey("master-key", passwordChars);

            final SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            final KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256, secureRandom);
            final SecretKey newMasterKey = keyGen.generateKey();

            final Enumeration<String> aliases = keystore.aliases();
            final List<String> clientKeyAliases = new ArrayList<>();
            while (aliases.hasMoreElements()) {
                final String alias = aliases.nextElement();
                if (!alias.equals("master-key") && !alias.equals("jwt-signing-key")) {
                    clientKeyAliases.add(alias);
                }
            }

            for (final String clientAlias : clientKeyAliases) {
                final SecretKeyEntry entry = (SecretKeyEntry) keystore.getEntry(clientAlias, new PasswordProtection(passwordChars));
                final SecretKeySpec wrappedKeySpec = (SecretKeySpec) entry.getSecretKey();

                final Cipher unwrapCipher = Cipher.getInstance("AES");
                unwrapCipher.init(Cipher.UNWRAP_MODE, oldMasterKey);
                final SecretKey unwrappedClientKey = (SecretKey) unwrapCipher.unwrap(wrappedKeySpec.getEncoded(), "AES", Cipher.SECRET_KEY);

                final Cipher wrapCipher = Cipher.getInstance("AES");
                wrapCipher.init(Cipher.WRAP_MODE, newMasterKey);
                final byte[] newEncryptedKey = wrapCipher.wrap(unwrappedClientKey);
                final SecretKeySpec newWrappedKeySpec = new SecretKeySpec(newEncryptedKey, "AES");

                final SecretKeyEntry newEntry = new SecretKeyEntry(newWrappedKeySpec);
                keystore.setEntry(clientAlias, newEntry, new PasswordProtection(passwordChars));
            }

            final SecretKeyEntry newMasterEntry = new SecretKeyEntry(newMasterKey);
            keystore.setEntry("master-key", newMasterEntry, new PasswordProtection(passwordChars));

            keyStoreHelper.saveKeyStore(keystore);
            Arrays.fill(passwordChars, '\0');
            System.out.println("Master-Key Rotation abgeschlossen und alle Client-Keys re-wrapped.");
        } catch (final Exception exception) {
            System.err.println("Fehler bei der Master-Key Rotation: " + exception.getMessage());
        }
    }
}
