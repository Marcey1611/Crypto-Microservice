package com.projectwork.cryptoservice.entity.models.keymanagement;

import lombok.Getter;
import lombok.Setter;

/**
 * ClientKeyData class that represents the key data for a client.
 * It contains the key alias and an initialization vector (IV).
 */
@Getter
public class ClientKeyData {
    private final String keyAlias;

    @Setter
    private byte[] iv;

    /**
     * Constructor to create a ClientKeyData instance with the specified key alias and IV.
     *
     * @param keyAlias the alias of the key
     * @param iv the initialization vector (IV) associated with the key
     */
    public ClientKeyData(final String keyAlias, final byte[] iv) {
        this.keyAlias = keyAlias;
        this.iv = iv;
    }
}
