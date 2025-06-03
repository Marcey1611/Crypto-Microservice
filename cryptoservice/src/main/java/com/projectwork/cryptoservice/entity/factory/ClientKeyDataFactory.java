package com.projectwork.cryptoservice.entity.factory;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.models.keymanagement.ClientKeyData;

/**
 * ClientKeyDataFactory class that creates instances of ClientKeyData.
 * This factory is used to encapsulate the creation logic for ClientKeyData objects.
 */
@Component
public class ClientKeyDataFactory {

    /**
     * Builds a ClientKeyData instance with the specified key alias and IV.
     *
     * @param keyAlias the alias of the key
     * @param iv the initialization vector (IV) associated with the key
     * @return a new ClientKeyData instance
     */
    public final ClientKeyData buildClientKeyData(final String keyAlias, final byte[] iv) {
        return new ClientKeyData(keyAlias, iv);
    }
}
