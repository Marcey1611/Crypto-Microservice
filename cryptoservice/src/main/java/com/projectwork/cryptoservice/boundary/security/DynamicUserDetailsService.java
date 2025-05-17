package com.projectwork.cryptoservice.boundary.security;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class DynamicUserDetailsService implements UserDetailsService {

    private KnownClientStore knownClientStore;
    private HttpServletRequest request;

    @Override
    public UserDetails loadUserByUsername(String cn) throws UsernameNotFoundException {
        String path = request.getRequestURI();

        if (("/crypto/keys/generate".equals(path) && !knownClientStore.isKnown(cn)) || ("/crypto/decrypt".equals(path) && !knownClientStore.isKnown(cn))) {
            System.out.println("New client detected: " + cn);
            knownClientStore.addClient(cn); // neuen Client registrieren
            return new User(cn, "", AuthorityUtils.createAuthorityList("ROLE_USER"));
        }

        if (knownClientStore.isKnown(cn)) {
            System.out.println("Known client: " + cn);
            return new User(cn, "", AuthorityUtils.createAuthorityList("ROLE_USER"));
        }

        throw new UsernameNotFoundException("Unknown CN: " + cn);
    }
}
