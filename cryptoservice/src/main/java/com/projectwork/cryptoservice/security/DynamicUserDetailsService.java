package com.projectwork.cryptoservice.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class DynamicUserDetailsService implements UserDetailsService {

    @Autowired
    private KnownClientStore knownClientStore;

    @Autowired
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
