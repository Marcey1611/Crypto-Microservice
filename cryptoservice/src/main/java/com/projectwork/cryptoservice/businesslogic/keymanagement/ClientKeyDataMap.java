package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.keymanagement.ClientKeyData;
import com.projectwork.cryptoservice.factory.ClientKeyDataFactory;

@Component
public class ClientKeyDataMap {
    @Autowired private ClientKeyDataFactory clientKeyDataFactory;
    private final Map<String, ClientKeyData> clientKeyDataMap = new ConcurrentHashMap<>();

    public boolean containsClient(final String clientName) {
        return clientKeyDataMap.containsKey(clientName);
    }

    public void addClientKeyAlias(final String clientName, final String keyAlias) {
        clientKeyDataMap.put(clientName, clientKeyDataFactory.buildClientKeyData(keyAlias, null));
    }

    public void removeKeyAliasFromMap(final String keyAlias) {
        System.out.println("Removing key alias from map: " + keyAlias);
        clientKeyDataMap.entrySet().removeIf(entry -> entry.getValue().getKeyAlias().equalsIgnoreCase(keyAlias));
    }

    public String getKeyAlias(final String clientName) {
        final ClientKeyData data = clientKeyDataMap.get(clientName);
        return data != null ? data.getKeyAlias() : null;
    }

    public String getClientName(final String keyAlias) {
        return clientKeyDataMap.entrySet().stream()
            .filter(entry -> entry.getValue().getKeyAlias().equalsIgnoreCase(keyAlias))
            .map(Map.Entry::getKey)
            .findFirst()
            .orElse(null);
    }
    
    public byte[] getIv(final String clientName) {
        final ClientKeyData data = clientKeyDataMap.get(clientName);
        return data != null ? data.getIv() : null;
    }

    public void putIv(final byte[] iv, final String clientName) {
        final ClientKeyData data = clientKeyDataMap.get(clientName);
        if (data == null) {
            throw new IllegalArgumentException("Client not found: " + clientName);
        }
        data.setIv(iv);
        clientKeyDataMap.put(clientName, data);
    }

    public void print() {
        if (clientKeyDataMap.isEmpty()) {
            System.out.println("Keine Client-Key-Mappings vorhanden.");
        } else {
            System.out.println("Aktuelle Client → KeyAlias + IV Mappings:");
            clientKeyDataMap.forEach((client, data) ->
                System.out.printf(" - %s => %s", client, data.getKeyAlias())
            );
        }
    }
    
}
