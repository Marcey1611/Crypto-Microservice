package com.projectwork.cryptoservice.boundary.security;

import com.projectwork.cryptoservice.boundary.authorization.AuthService;
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
 * DynamicUserDetailsService is a custom UserDetailsService that dynamically registers and authorizes clients
 * based on their Common Name (CN) and the requested path.
 *
 * SCPs:
 * - [78] Use a single site-wide component to check access authorization (via AuthService)
 */
@RequiredArgsConstructor
@Component
public class DynamicUserDetailsService implements UserDetailsService {

    private static final Logger LOGGER = LoggerFactory.getLogger(DynamicUserDetailsService.class);

    private final HttpServletRequest request;
    private final AuthService authService;

    @Override
    public UserDetails loadUserByUsername(final String clientName) throws UsernameNotFoundException {
        final String path = this.request.getRequestURI();
        final String logMsg = String.format("\n\n====================================================================== New request at '%s' from client '%s' ======================================================================\n", path, clientName);
        LOGGER.info(logMsg);

        LOGGER.info("Authentication attempt: CN='{}' on path '{}'", clientName, path);
        this.authService.authorizePathAccess(clientName, path);

        LOGGER.debug("Access granted for CN='{}' to path '{}'", clientName, path);
        final List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
        return new User(clientName, "", authorities);
    }
}
