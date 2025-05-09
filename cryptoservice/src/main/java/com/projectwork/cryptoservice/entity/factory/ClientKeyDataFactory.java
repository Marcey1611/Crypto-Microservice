package com.projectwork.cryptoservice.entity.factory;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.models.keymanagement.ClientKeyData;

@Component
public class ClientKeyDataFactory {
    
    public ClientKeyData buildClientKeyData(final String keyAlias, final byte[] iv) {
        return new ClientKeyData(keyAlias, iv);
    }
}
