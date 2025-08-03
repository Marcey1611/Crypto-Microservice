package com.projectwork.cryptoservice.boundary.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Early IP-based Rate Limiting Filter.
 * This filter limits the number of requests per IP address before authentication.
 * SCPs:
 * - [94] Limit the number of transactions a single user/device can perform in a given time
 * - [114] Logging controls should support both success and failure of specified security events
 * - [123] Log all access control failures --> here we log when a user exceeds the rate limit
 */
@Component
public class IpRateLimitingFilter extends GenericFilterBean {

    private static final Logger LOGGER = LoggerFactory.getLogger(IpRateLimitingFilter.class);

    private static final int MAX_REQUESTS_PER_MINUTE = 60;
    private static final long TIME_WINDOW_MS = 60_000L;

    private final Map<String, RequestCounter> requestMap = new ConcurrentHashMap<>();

    @Override
    public final void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {

        LOGGER.debug("Processing ip rate limiting filter for requesting IP.");

        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final HttpServletResponse httpResponse = (HttpServletResponse) response;

        final String ipAddress = this.getClientIp(httpRequest);

        final long now = System.currentTimeMillis();
        final RequestCounter counter = this.requestMap.computeIfAbsent(ipAddress, k -> new RequestCounter());

        synchronized (counter) {
            if (TIME_WINDOW_MS < now - counter.startTime) {
                counter.startTime = now;
                counter.count = 1;
            } else {
                counter.count++;
            }

            if (MAX_REQUESTS_PER_MINUTE < counter.count) {
                final int httpStatusCode = HttpStatus.TOO_MANY_REQUESTS.value();
                httpResponse.setStatus(httpStatusCode);
                httpResponse.getWriter().write("Rate limit exceeded..");
                LOGGER.debug("Requesting IP exceeded rate limit.");
                return;
            }
        }

        LOGGER.debug("IP rate limiting check passed for requesting IP.");
        chain.doFilter(request, response);
    }

    private String getClientIp(final HttpServletRequest request) {
        return request.getRemoteAddr();
    }

    private static class RequestCounter {
        long startTime = System.currentTimeMillis();
        int count = 0;
    }
}
