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

@RequiredArgsConstructor
public class ClientAccessControlFilter extends GenericFilterBean {

    private final KnownClientStore knownClientStore;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String path = httpRequest.getRequestURI();
        Principal principal = httpRequest.getUserPrincipal();

        if (principal != null) {
            String cn = principal.getName();

            // Neue Clients dürfen nur auf diese Pfade zugreifen
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
