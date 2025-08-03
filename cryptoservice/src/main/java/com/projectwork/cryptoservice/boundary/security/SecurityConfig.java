package com.projectwork.cryptoservice.boundary.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.context.SecurityContextHolderFilter;


/**
 * Security configuration for the CryptoService application.
 * This configuration sets up security rules for the endpoints.
 * SCPs:
 * - [94] Limit the number of transactions a single user/device can perform in a given time
 * - [143] Implement encryption for the transmission of all sensitive information --> communication over mtls
 * - [144] TLS certificates should be valid and have the correct domain name, not be expired, and be installed with intermediate certificates when required --> see mtls files and mtls readme file
 * - [145] Failed TLS connections should not fall back to an insecure connection --> spring boot standard config
 * - [146] Utilize TLS for all authenticated access and all other sensitive information --> all endpoints are accessable just over mtls
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final IpRateLimitingFilter ipRateLimitingFilter;
    private final PrincipalRateLimitingFilter principalRateLimitingFilter;

    /**
     * Provides a UserDetailsService that returns a User with no authorities.
     * This is used for X.509 authentication where the user details are not needed.
     *
     * @return a UserDetailsService instance
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> new User(username, "", AuthorityUtils.NO_AUTHORITIES);
    }

    /**
     * Configures the security filter chain for the application.
     * This method sets up the authorization rules, X.509 authentication,
     * and adds custom filters for rate limiting.
     *
     * @param http the HttpSecurity object to configure
     * @return a SecurityFilterChain instance
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )
                .x509(x509 -> x509
                        .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                        .userDetailsService(userDetailsService())
                )
                .addFilterBefore(this.ipRateLimitingFilter, SecurityContextHolderFilter.class)
                .addFilterAfter(this.principalRateLimitingFilter, FilterSecurityInterceptor.class)
                .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
