package com.projectwork.cryptoservice.businesslogic.keymanagement;

import com.projectwork.cryptoservice.entity.factory.ClientKeyDataFactory;
import com.projectwork.cryptoservice.entity.models.keymanagement.ClientKeyData;
import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ClientKeyRegistry class that manages the registration and retrieval of client keys.
 * It allows for registering clients with their key aliases, checking if a client exists,
 * and retrieving key aliases and IVs associated with clients.
 */
@RequiredArgsConstructor
@Component
public class ClientKeyRegistry {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientKeyRegistry.class);

    private final ClientKeyDataFactory clientKeyDataFactory;
    private final Map<String, ClientKeyData> clientKeyDataMap = new ConcurrentHashMap<>();
    private final ErrorHandler errorHandler;

    /**
     * Checks if a client with the given name exists in the registry.
     *
     * @param clientName the name of the client to check
     * @return true if the client exists, false otherwise
     */
    public final boolean hasClient(final String clientName) {
        final boolean exists = this.clientKeyDataMap.containsKey(clientName);
        LOGGER.debug("Checking if client '{}' exists: {}", clientName, exists);
        return exists;
    }

    /**
     * Registers a client with the given name and key alias.
     *
     * @param clientName the name of the client to register
     * @param keyAlias the key alias associated with the client
     */
    public final void registerClientKey(final String clientName, final String keyAlias) {
        final ClientKeyData clientKeyData = this.clientKeyDataFactory.buildClientKeyData(keyAlias, null);
        this.clientKeyDataMap.put(clientName, clientKeyData);
        LOGGER.info("Registered new client '{}', key alias '{}'", clientName, keyAlias);
    }

    /**
     * Checks if a client with the given key alias exists in the registry.
     *
     * @param keyAlias the key alias to check
     */
    public void removeClientByKeyAlias(final String keyAlias) {
        final long before = (long) this.clientKeyDataMap.size();
        this.clientKeyDataMap.entrySet().removeIf(entry
                -> entry.getValue().getKeyAlias().equalsIgnoreCase(keyAlias));
        final long after = (long) this.clientKeyDataMap.size();
        LOGGER.info("Removed client(s) with key alias '{}'. Size before: {}, after: {}", keyAlias, before, after);
    }

    /**
     * Retrieves the key alias for a given client name.
     *
     * @param clientName the name of the client
     * @return the key alias associated with the client, or null if the client does not exist
     */
    public String getKeyAliasForClient(final String clientName) {
        final ClientKeyData data = this.clientKeyDataMap.get(clientName);
        return null != data ? data.getKeyAlias() : null;
    }

    /**
     * Retrieves the client name associated with a given key alias.
     *
     * @param keyAlias the key alias to search for
     * @return the client name associated with the key alias, or null if not found
     */
    public final String getClientNameByKeyAlias(final String keyAlias) {
        return this.clientKeyDataMap.entrySet().stream()
            .filter(entry -> entry.getValue().getKeyAlias().equalsIgnoreCase(keyAlias))
            .map(Map.Entry::getKey)
            .findFirst()
            .orElse(null);
    }

    /**
     * Retrieves the IV (Initialization Vector) for a given client.
     *
     * @param clientName the name of the client
     * @return the IV associated with the client, or null if the client does not exist
     */
    public final byte[] getIvForClient(final String clientName) {
        final ClientKeyData data = this.clientKeyDataMap.get(clientName);
        return null != data ? data.getIv() : null;
    }

    /**
     * Updates the IV (Initialization Vector) for a given client.
     *
     * @param clientName the name of the client
     * @param iv the new IV to set for the client
     * @throws BadRequestException if the client does not exist
     */
    public final void updateIvForClient(final String clientName, final byte[] iv) {
        final ClientKeyData data = this.clientKeyDataMap.get(clientName);
        if (null == data) {
            throw this.errorHandler.handleError(
                ErrorCode.CLIENT_NOT_FOUND,
                clientName,
        "While trying to update IV for client."
            );
        }
        data.setIv(iv);
        this.clientKeyDataMap.put(clientName, data);
        LOGGER.info("Updated IV for client '{}'", clientName);
    }
}
