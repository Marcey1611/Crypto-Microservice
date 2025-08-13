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
 * PrincipalRateLimitingFilter is a servlet filter that limits the number of requests
 * a user can make to the server within a specified time window.
 * SCPs:
 * - [94] Limit the number of transactions a single user/device can perform in a given time
 * - [114] Logging controls should support both success and failure of specified security events
 * - [123] Log all access control failures --> here we log warn when a user exceeds the rate limit
 */
@Component
public class PrincipalRateLimitingFilter extends OncePerRequestFilter {

    private static final int MAX_REQUESTS_PER_MINUTE = 10;
    private static final long TIME_WINDOW_MS = 60_000L;
    private static final Logger LOGGER = LoggerFactory.getLogger(PrincipalRateLimitingFilter.class);

    private final Map<String, RequestCounter> requestMap = new ConcurrentHashMap<>();

    @Override
    protected final void doFilterInternal(final HttpServletRequest request,
                                          final HttpServletResponse response,
                                          final FilterChain filterChain) throws ServletException, IOException {

        LOGGER.debug("Processing rate limiting for requesting client.");
        final Principal principal = request.getUserPrincipal();
        final String clientName = principal.getName();

        final long now = System.currentTimeMillis();
        final RequestCounter counter = this.requestMap.computeIfAbsent(clientName, k -> new RequestCounter());

        if (TIME_WINDOW_MS < now - counter.startTime) {
            counter.startTime = now;
            counter.count = 1;
        } else {
            counter.count++;
        }

        if (MAX_REQUESTS_PER_MINUTE < counter.count) {
            final int httpStatus = HttpStatus.TOO_MANY_REQUESTS.value();
            response.setStatus(httpStatus);
            response.getWriter().write("Rate limit exceeded.");
            LOGGER.warn("Rate limit exceeded for requesting client.");
            return;
        }

        LOGGER.debug("Rate limiting check passed for requesting client.");
        filterChain.doFilter(request, response);
    }

    private static class RequestCounter {
        long startTime = System.currentTimeMillis();
        int count = 0;
    }
}