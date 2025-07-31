package com.projectwork.cryptoservice.boundary.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.security.Principal;

/**
 * ClientAccessControlFilter is a servlet filter that checks if the client is known
 * and whether they are allowed to access certain endpoints.
 * It allows new clients to access specific endpoints for registration or key generation.
 */
@RequiredArgsConstructor
public class ClientAccessControlFilter extends GenericFilterBean {

    private final KnownClientStore knownClientStore;

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {

        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final String path = httpRequest.getRequestURI();
        final Principal principal = httpRequest.getUserPrincipal();

        if (principal != null) {
            final String cn = principal.getName();

            boolean isNewClient = !knownClientStore.isKnown(cn);
            boolean pathAllowsNewClients = path.equals("/crypto/keys/generate") || path.equals("/crypto/decrypt");

            if (isNewClient && !pathAllowsNewClients) {
                ((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN, "Client not registered.");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
