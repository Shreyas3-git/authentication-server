package com.bookmyshow.oauth.authentication_server.controller;

import com.bookmyshow.oauth.authentication_server.entity.User;
import com.bookmyshow.oauth.authentication_server.repository.UserRepository;
import com.bookmyshow.oauth.authentication_server.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.Set;

@RestController
public class UserController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenService tokenService;

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
}