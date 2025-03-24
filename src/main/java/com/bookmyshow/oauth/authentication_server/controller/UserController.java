package com.bookmyshow.oauth.authentication_server.controller;

import com.bookmyshow.oauth.authentication_server.entity.User;
import com.bookmyshow.oauth.authentication_server.repository.UserRepository;
import com.bookmyshow.oauth.authentication_server.service.TokenService;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Set;


@RestController
public class UserController {

    private final Logger log = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenService tokenService;


    private final JWKSource jwkSource;


    public UserController(JWKSource jwkSource) {
        this.jwkSource = jwkSource;
    }

    @PostMapping("/register/roles")
    public User register(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            user.setRoles(Set.of("USER")); // Default role
        }
        return userRepository.save(user);
    }

    @PostMapping("oauth/token")
    public Map<String,String> oauthToken(@RequestBody Map<String, String> loginRequest) {
        return tokenService.issueToken(loginRequest);
    }


    @GetMapping("/oauth2/jwks")
    public ResponseEntity<Map<String, Object>> getJwks() {
        try {
            // Create a matcher that selects all JWKs
            JWKSelector selector = new JWKSelector(new JWKMatcher.Builder().build());
            List<JWK> jwkList = jwkSource.get(selector, null);
            JWKSet jwkSet = new JWKSet(jwkList);
            return ResponseEntity.ok(jwkSet.toJSONObject());
        } catch (Exception e) {
            log.error("Failed to retrieve JWKS", e);
            return ResponseEntity.status(500).build();
        }
    }


}