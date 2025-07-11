package com.projectwork.cryptoservice.boundary.security;

import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * KnownClientStore is a component that maintains a set of known clients.
 * It provides methods to check if a client is known and to add new clients.
 */
@Component
public class KnownClientStore {

    private final Set<String> knownClients = ConcurrentHashMap.newKeySet();

    /**
     * Checks if the client is new based on the request path and known client store.
     *
     * @param cn  the Common Name (CN) of the client
     * @return true if the client is new, false otherwise
     */
    public final boolean isKnown(final String cn) {
        return this.knownClients.contains(cn);
    }

    /**
     * Adds a new client to the known clients set.
     *
     * @param cn the Common Name (CN) of the client to be added
     */
    public final void addClient(final String cn) {
        this.knownClients.add(cn);
    }
}