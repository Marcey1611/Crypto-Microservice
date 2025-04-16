package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

@Component
public class ClientKeyAliasMap {
    private final Map<String, String> clientKeyAliasMap = new ConcurrentHashMap<>();

    public boolean containsClient(final String clientName) {
        return clientKeyAliasMap.containsKey(clientName);
    }

    public String addClientKeyAlias(final String clientName, final String keyAlias) {
        return clientKeyAliasMap.put(clientName, keyAlias);
    }

    public void removeKeyAliasFromMap(final String keyAlias) {
        System.out.println("Removing key alias from map: " + keyAlias);
        clientKeyAliasMap.entrySet().removeIf(entry -> entry.getValue().equals(keyAlias.toLowerCase()));
    }

    public String getKeyAlias(final String clientName) {
        return clientKeyAliasMap.get(clientName);
    }

    public void print() {
        if (clientKeyAliasMap.isEmpty()) {
            System.out.println("Keine Client-Key-Mappings vorhanden.");
        } else {
            System.out.println("Aktuelle Client → KeyAlias Mappings:");
            clientKeyAliasMap.forEach((client, alias) ->
                System.out.printf(" - %s => %s%n", client, alias)
            );
        }
    }
    
}
