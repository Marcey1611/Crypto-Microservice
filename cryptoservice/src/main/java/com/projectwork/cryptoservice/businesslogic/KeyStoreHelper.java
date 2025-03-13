package com.projectwork.cryptoservice.businesslogic;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import javax.crypto.SecretKey;

@Component
public class KeyStoreHelper {
    private static final String KEYSTORE_PATH = "keystores/keystore.jks";
    private static final String KEYSTORE_PASSWORD = "CryptoMicroservice2025!"; // Sicher speichern!

    // Lädt den Keystore
    private KeyStore loadKeyStore() throws Exception {

        KeyStore keystore = KeyStore.getInstance("JCEKS");        

        try (InputStream is = new ClassPathResource(KEYSTORE_PATH).getInputStream()) { 
            System.out.println("Lade Keystore: " + new ClassPathResource(KEYSTORE_PATH).exists());
       
            keystore.load(is, KEYSTORE_PASSWORD.toCharArray());

        }
        return keystore;
    }

    // Speichert den Keystore
    private void saveKeyStore(KeyStore keystore) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(KEYSTORE_PATH)) {
            keystore.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }
    }

    // Speichert einen neuen Schlüssel im Keystore
    public void storeKey(String alias, SecretKey key) throws Exception {

        KeyStore keystore = loadKeyStore();

        KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(key);
        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(KEYSTORE_PASSWORD.toCharArray());
        keystore.setEntry(alias, keyEntry, protection);

        saveKeyStore(keystore);
    }

    // Holt einen Schlüssel aus dem Keystore
    public SecretKey getKey(String alias) throws Exception {
        KeyStore keystore = loadKeyStore();
        return (SecretKey) keystore.getKey(alias, KEYSTORE_PASSWORD.toCharArray());
    }
}
