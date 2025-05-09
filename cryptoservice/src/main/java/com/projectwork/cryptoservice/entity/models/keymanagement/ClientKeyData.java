package com.projectwork.cryptoservice.entity.models.keymanagement;

public class ClientKeyData {
    private final String keyAlias;
    private byte[] iv;

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
    public void setIv(final byte[] iv) {
        this.iv = iv;
    }
}
