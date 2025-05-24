package com.projectwork.cryptoservice.businesslogic.keymanagement;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import com.projectwork.cryptoservice.entity.factory.ClientKeyDataFactory;
import com.projectwork.cryptoservice.entity.models.keymanagement.ClientKeyData;
import com.projectwork.cryptoservice.errorhandling.exceptions.BadRequestException;
import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class ClientKeyRegistry {
    private final ClientKeyDataFactory clientKeyDataFactory;
    private final Map<String, ClientKeyData> clientKeyDataMap = new ConcurrentHashMap<>();

    public boolean hasClient(final String clientName) {
        return clientKeyDataMap.containsKey(clientName);
    }

    public void registerClientKey(final String clientName, final String keyAlias) {
        clientKeyDataMap.put(clientName, clientKeyDataFactory.buildClientKeyData(keyAlias, null));
    }

    public void removeClientByKeyAlias(final String keyAlias) {
        clientKeyDataMap.entrySet().removeIf(entry -> {
            boolean match = entry.getValue().getKeyAlias().equalsIgnoreCase(keyAlias);
            return match;
        });
    }

    public String getKeyAliasForClient(final String clientName) {
        final ClientKeyData data = clientKeyDataMap.get(clientName);
        return data != null ? data.getKeyAlias() : null;
    }

    public String getClientNameByKeyAlias(final String keyAlias) {
        return clientKeyDataMap.entrySet().stream()
            .filter(entry -> entry.getValue().getKeyAlias().equalsIgnoreCase(keyAlias))
            .map(Map.Entry::getKey)
            .findFirst()
            .orElse(null);
    }

    public byte[] getIvForClient(final String clientName) {
        final ClientKeyData data = clientKeyDataMap.get(clientName);
        return data != null ? data.getIv() : null;
    }

    public void updateIvForClient(final String clientName, final byte[] iv) {
        final ClientKeyData data = clientKeyDataMap.get(clientName);
        if (data == null) {
            throw new BadRequestException(ErrorCode.CLIENT_NOT_FOUND.builder()
                .withUserMsgFormatted(clientName)
                .withContext("While trying to update IV for client.")
                .withException(null)
                .build()
            );
        }
        data.setIv(iv);
        clientKeyDataMap.put(clientName, data);
    }
}
