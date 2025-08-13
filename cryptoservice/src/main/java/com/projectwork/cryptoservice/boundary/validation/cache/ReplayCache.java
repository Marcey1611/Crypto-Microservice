package com.projectwork.cryptoservice.boundary.validation.cache;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class ReplayCache {
    private final ConcurrentHashMap<String, Long> map = new ConcurrentHashMap<>();

    /**
     * Registers a JWT ID (jti) with its expiration time in the cache.
     * If the jti already exists, it will not overwrite the existing entry.
     *
     * @param jti            the JWT ID to register
     * @param expEpochSeconds the expiration time in epoch seconds
     */
    public void register(final String jti, final long expEpochSeconds) {
        map.putIfAbsent(jti, expEpochSeconds);
    }

    /**
     * Consumes a JWT ID (jti) from the cache, removing it if it exists.
     *
     * @param jti the JWT ID to consume
     * @return true if the jti was found and removed, false otherwise
     */
    public boolean consumeOnce(final String jti) {
        return map.remove(jti) != null;
    }

    /**
     * Checks if a JWT ID (jti) is already registered in the cache.
     */
    @Scheduled(fixedDelay = 60_000)
    public void cleanup() {
        final long now = Instant.now().getEpochSecond();
        map.entrySet().removeIf(e -> e.getValue() < now);
    }
}
