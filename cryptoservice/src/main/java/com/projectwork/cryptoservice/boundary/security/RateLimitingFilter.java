package com.projectwork.cryptoservice.boundary.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * RateLimitingFilter is a servlet filter that limits the number of requests
 * a user can make to the server within a specified time window.
 *
 * SCPs:
 * - [94] Limit the number of transactions a single user/device can perform in a given time
 * - [114] Logging controls should support both success and failure of specified security events
 * - [123] Log all access control failures --> here we log warn when a user exceeds the rate limit
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final int MAX_REQUESTS_PER_MINUTE = 10;
    private static final long TIME_WINDOW_MS = 60_000;
    private static final Logger LOGGER = LoggerFactory.getLogger(RateLimitingFilter.class);

    private final Map<String, RequestCounter> requestMap = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain) throws ServletException, IOException {

        LOGGER.debug("Processing request for rate limiting");
        final Principal principal = request.getUserPrincipal();
        final String clientName = principal.getName();

        final long now = System.currentTimeMillis();
        final RequestCounter counter = requestMap.computeIfAbsent(clientName, k -> new RequestCounter());

        synchronized (counter) {
            if (now - counter.startTime > TIME_WINDOW_MS) {
                counter.startTime = now;
                counter.count = 1;
            } else {
                counter.count++;
            }

            if (counter.count > MAX_REQUESTS_PER_MINUTE) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.getWriter().write("Rate limit exceeded.");
                LOGGER.warn("Rate limit exceeded for user.");
                return;
            }
        }

        filterChain.doFilter(request, response);
        LOGGER.debug("Rate limiting check passed for user.");
    }

    private static class RequestCounter {
        long startTime = System.currentTimeMillis();
        int count = 0;
    }
}
