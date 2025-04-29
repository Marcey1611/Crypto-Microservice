package com.projectwork.cryptoservice.entity.keymanagement;

public class ClientKeyData {
    private final String keyAlias;
    private final byte[] iv;

    public ClientKeyData(final String keyAlias, final byte[] iv) {
        this.keyAlias = keyAlias;
        this.iv = iv;
    }

    public String getKeyAlias() {
        return keyAlias;
    }
    public byte[] getIv() {
        return iv;
    }
}
