package com.projectwork.cryptoservice.boundary.authorization;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AuthRegistry class that manages the registration and access control of key aliases.
 */
@Component
@RequiredArgsConstructor
public class AuthRegistry {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthRegistry.class);

    private final ConcurrentHashMap<String, Set<String>> accessMap = new ConcurrentHashMap<>();

    /**
     * Registers a key alias with a set of allowed clients.
     *
     * @param keyAlias the alias of the key to register
     * @param allowedClients the set of clients allowed to access the key
     */
    public final void registerKeyAlias(final String keyAlias, final Set<String> allowedClients) {
        final int size = allowedClients.size();
        this.accessMap.putIfAbsent(keyAlias, ConcurrentHashMap.newKeySet(size));
        this.accessMap.get(keyAlias).addAll(allowedClients);
        LOGGER.debug("Registered new keyAlias with access for some clients.");
    }

    /**
     * Grants access to a key alias for a specific client.
     *
     * @param keyAlias the alias of the key to grant access to.
     * @param clientName the name of the client to grant access to.
     */
    public final void grantAccess(final String keyAlias, final String clientName) {
        final Set<String> clients = this.accessMap.get(keyAlias);
        clients.add(clientName);
        LOGGER.debug("Granted access to specific keyAlias for specific client.");
    }

    /**
     * Revokes access to a key alias for a specific client.
     *
     * @param keyAlias the alias of the key to revoke access from.
     * @param clientName the name of the client whose access is to be revoked.
     */
    public final void revokeAccess(final String keyAlias, final String clientName) {
        final Set<String> clients = this.accessMap.get(keyAlias);
        clients.remove(clientName);
        LOGGER.debug("Revoked access to specific keyAlias for specific client");
    }

    /**
     * Checks if a client has access to a specific key alias.
     *
     * @param keyAlias the alias of the key to check access for.
     * @param clientName the name of the client whose access is to be checked.
     * @return true if the client has access, false otherwise.
     */
    public final boolean isAccessAllowed(final String keyAlias, final String clientName) {
        final Set<String> clients = this.accessMap.get(keyAlias);
        return null != clients && clients.contains(clientName);
    }
}
