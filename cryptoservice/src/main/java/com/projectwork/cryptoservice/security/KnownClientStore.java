package com.projectwork.cryptoservice.security;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

@Component
public class KnownClientStore {
    private final Set<String> knownClients = ConcurrentHashMap.newKeySet();

    public boolean isKnown(String cn) {
        return knownClients.contains(cn);
    }

    public void addClient(String cn) {
        knownClients.add(cn);
    }
}
