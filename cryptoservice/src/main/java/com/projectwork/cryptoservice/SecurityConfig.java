package com.projectwork.cryptoservice;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        System.out.println("1---------------------------------------------------------------");
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .x509(x509 -> x509
                .subjectPrincipalRegex("CN\\s*=\\s*([^,]+)")
                .userDetailsService(userDetailsService()) // wichtig!
            );
        System.out.println("2----------------------------------------------------------------");
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            // Zum Testen: Erlaube den CN "client"
            System.out.println("SecConfig ---------------------------------------------------------------------------------------------------------------------------------------");
            if ("client1".equalsIgnoreCase(username)) {
                return User.withUsername("client1")
                    .password("pass:CryptoMicroservice2025!") // X.509 braucht kein Passwort
                    .authorities("ROLE_USER")
                    .accountExpired(false)
                    .accountLocked(false)
                    .credentialsExpired(false)
                    .disabled(false)
                    .build();
            }
            System.out.println("Oho------------------------------------------------------------------------------------------------------------------------------------------------");
            throw new UsernameNotFoundException("Client nicht erlaubt: " + username);
        };
    }
}
