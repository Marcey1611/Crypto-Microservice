package com.projectwork.cryptoservice.factory;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.keymanagement.ClientKeyData;

@Component
public class ClientKeyDataFactory {
    
    public ClientKeyData buildClientKeyData(final String keyAlias, final byte[] iv) {
        return new ClientKeyData(keyAlias, iv);
    }
}
