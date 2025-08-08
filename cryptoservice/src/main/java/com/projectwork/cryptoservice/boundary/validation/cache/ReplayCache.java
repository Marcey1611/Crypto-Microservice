package com.projectwork.cryptoservice.boundary.validation.cache;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class ReplayCache {
    private final ConcurrentHashMap<String, Long> map = new ConcurrentHashMap<>();

    public void register(final String jti, final long expEpochSeconds) {
        map.putIfAbsent(jti, expEpochSeconds);
    }

    /** @return true = erster Gebrauch, false = Replay */
    public boolean consumeOnce(final String jti) {
        return map.remove(jti) != null;
    }

    @Scheduled(fixedDelay = 60_000)
    public void cleanup() {
        final long now = Instant.now().getEpochSecond();
        map.entrySet().removeIf(e -> e.getValue() < now);
    }
}
