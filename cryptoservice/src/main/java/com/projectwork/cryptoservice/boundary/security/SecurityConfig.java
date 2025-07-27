package com.projectwork.cryptoservice.boundary.security;

import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public class SecurityConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityConfig.class);

    private final DynamicUserDetailsService dynamicUserDetailsService;

    /**
     * Configures the security filter chain for the application.
     * This method defines which endpoints are accessible and applies security rules.
     *
     * @param http the HttpSecurity object to configure
     * @return the configured SecurityFilterChain
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        LOGGER.info("SecurityFilterChain for CryptoService initialized.");

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/crypto/keys/generate").authenticated() // <-- wichtig!
                        .requestMatchers("/crypto/jwt/generate").permitAll()
                        .requestMatchers("/crypto/encrypt").permitAll()
                        .requestMatchers("/crypto/decrypt").authenticated()
                        .anyRequest().denyAll()
                )
                .x509(x509 -> x509
                        .subjectPrincipalRegex("CN=(.*?)(?:,|$)") // <-- CN aus dem Zertifikat extrahieren
                        .userDetailsService(dynamicUserDetailsService) // <-- dein Custom-Service
                )
                .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
