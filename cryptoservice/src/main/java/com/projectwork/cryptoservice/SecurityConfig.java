package com.projectwork.cryptoservice;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
            .requestMatchers("/crypto/keys/generate").authenticated()
            .requestMatchers("/crypto/jwt/generate").authenticated()
            .requestMatchers("/crypto/encrypt").authenticated()
            .requestMatchers("/crypto/decrypt").authenticated()
            .anyRequest().denyAll())
            .x509(x509 -> x509
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(userDetailsService())
            )
            .csrf(csrf -> csrf.disable());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            if ("Client1".equals(username)) {
                return new User("Client1", "", AuthorityUtils.createAuthorityList("ROLE_USER"));
            }
            throw new UsernameNotFoundException("User not found: " + username);
        };
    }
}
