package com.projectwork.cryptoservice.boundary.security;

import com.projectwork.cryptoservice.errorhandling.util.ErrorCode;
import com.projectwork.cryptoservice.errorhandling.util.ErrorHandler;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * DynamicUserDetailsService is a custom UserDetailsService that dynamically registers and retrieves user details based on the Common Name (CN).
 * It checks if the CN is known and registers new clients when necessary.
 */
@RequiredArgsConstructor
@Component
public class DynamicUserDetailsService implements UserDetailsService {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamicUserDetailsService.class);

    private final KnownClientStore knownClientStore;
    private final HttpServletRequest request;
    private final ErrorHandler errorHandler;

    /**
     * Constructs a DynamicUserDetailsService with the specified username.
     *
     * @param username the username of the user to be registered or retrieved
     */
    @Override
    public final UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        final String path = this.request.getRequestURI();
        LOGGER.debug("User authentication attempt for CN='{}' on path '{}'", username, path);

        final List<GrantedAuthority> roleUser = AuthorityUtils.createAuthorityList("ROLE_USER");
        if (this.isNewClient(username, path)) {
            LOGGER.info("Registering new client CN='{}' based on request to '{}'", username, path);
            this.knownClientStore.addClient(username);
            return new User(username, "", roleUser);
        }

        if (this.knownClientStore.isKnown(username)) {
            LOGGER.debug("Known client CN='{}' authenticated successfully.", username);
            return new User(username, "", roleUser);
        }

        final String context = String.format("While trying to authenticate user with CN: %s", username);
        throw this.errorHandler.handleError(
                context,
                username,
                ErrorCode.UNKNOWN_CLIENT
        );
    }

    /**
     * Checks if the client is new based on the request path and known client store.
     *
     * @param username the username of the client
     * @param path     the request path
     * @return true if the client is new, false otherwise
     */
    private boolean isNewClient(final String username, final String path) {
        return ("/crypto/keys/generate".equals(path) && !this.knownClientStore.isKnown(username)) || ("/crypto/decrypt".equals(path) && !this.knownClientStore.isKnown(username));
    }
}