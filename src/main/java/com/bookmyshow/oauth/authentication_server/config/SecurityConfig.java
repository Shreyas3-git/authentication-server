package com.bookmyshow.oauth.authentication_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf(csrf -> csrf.disable())
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers(
//                                "/register/roles",
//                                "/login",
//                                "/oauth/token",
//                                "/api/public/**",
//                                "/.well-known/openid-configuration", // Allow OIDC discovery
//                                "/oauth2/jwks" // Allow JWKS endpoint
//                        ).permitAll()
//                        .requestMatchers("/bookmyshow/profile").hasRole("USER")
//                        .requestMatchers("/bookmyshow/admin").hasRole("ADMIN")
//                        .anyRequest().authenticated()
//                )
//                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//        return http.build();
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/register/roles",
                                "/login",
                                "/oauth/token",
                                "/api/public/**",
                                // Add these lines to permit OIDC and JWKS endpoints
                                "/.well-known/openid-configuration",
                                "/oauth2/jwks"
                        ).permitAll()
                        .requestMatchers("/bookmyshow/profile").hasRole("USER")
                        .requestMatchers("/bookmyshow/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri("http://localhost:9000/.well-known/jwks.json").build();
    }
}