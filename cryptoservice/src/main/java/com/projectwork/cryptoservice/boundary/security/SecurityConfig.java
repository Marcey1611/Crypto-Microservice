package com.projectwork.cryptoservice.boundary.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Security configuration for the CryptoService application.
 * This configuration sets up security rules for the endpoints.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityConfig.class);

    /**
     * Configures the security filter chain for the application.
     * This method defines which endpoints are accessible and applies security rules.
     *
     * @param http the HttpSecurity object to configure
     * @return the configured SecurityFilterChain
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        LOGGER.info("SecurityFilterChain for CryptoService initialized.");
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/crypto/keys/generate").permitAll()
                .requestMatchers("/crypto/jwt/generate").permitAll()
                .requestMatchers("/crypto/encrypt").permitAll()
                .requestMatchers("/crypto/decrypt").permitAll()
                .anyRequest().denyAll()
            )
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
