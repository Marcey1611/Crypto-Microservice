package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.projectwork.cryptoservice.errorhandling.util.ErrorDetail;
import com.projectwork.cryptoservice.errorhandling.util.ErrorDetailBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.factory.ClientKeyDataFactory;
import com.projectwork.cryptoservice.entity.models.keymanagement.ClientKeyData;
import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

import lombok.RequiredArgsConstructor;

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

    /**
     * Checks if a client with the given name exists in the registry.
     *
     * @param clientName the name of the client to check
     * @return true if the client exists, false otherwise
     */
    public final boolean hasClient(final String clientName) {
        System.out.println("hasClient");
        return this.clientKeyDataMap.containsKey(clientName);
    }

    /**
     * Registers a client with the given name and key alias.
     *
     * @param clientName the name of the client to register
     * @param keyAlias the key alias associated with the client
     */
    public final void registerClientKey(final String clientName, final String keyAlias) {
        System.out.println("registerClientKey");
        final ClientKeyData clientKeyData = this.clientKeyDataFactory.buildClientKeyData(keyAlias, null);
        this.clientKeyDataMap.put(clientName, clientKeyData);
    }

    /**
     * Checks if a client with the given key alias exists in the registry.
     *
     * @param keyAlias the key alias to check
     */
    public void removeClientByKeyAlias(final String keyAlias) {
        System.out.println("removeClientByKeyAlias");
        this.clientKeyDataMap.entrySet().removeIf(entry
                -> entry.getValue().getKeyAlias().equalsIgnoreCase(keyAlias));
    }

    /**
     * Retrieves the key alias for a given client name.
     *
     * @param clientName the name of the client
     * @return the key alias associated with the client, or null if the client does not exist
     */
    public String getKeyAliasForClient(final String clientName) {
        System.out.println("getKeyAliasForClient");
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
        System.out.println("getClientNameByKeyAlias");
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
        System.out.println("getIvForClient");
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
        System.out.println("updateIvForClient");
        final ClientKeyData data = this.clientKeyDataMap.get(clientName);
        if (null == data) {
            final ErrorCode errorCode = ErrorCode.CLIENT_NOT_FOUND;
            final ErrorDetailBuilder errorDetailBuilder = errorCode.builder();
            errorDetailBuilder.withUserMsgFormatted(clientName);
            errorDetailBuilder.withContext("While trying to update IV for client.");
            errorDetailBuilder.withException(null);
            final ErrorDetail errorDetail = errorDetailBuilder.build();
            throw new BadRequestException(errorDetail);
        }
        data.setIv(iv);
        this.clientKeyDataMap.put(clientName, data);
    }
}
