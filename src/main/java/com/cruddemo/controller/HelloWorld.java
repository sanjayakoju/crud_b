package com.cruddemo.controller;

import com.cruddemo.security.JWTTokenProvider;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class HelloWorld {

    @Autowired
    JWTTokenProvider jwtTokenProvider;
    @Autowired
    private final AuthenticationManager authenticationManager;

    public HelloWorld(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @GetMapping
    public String hello() throws JsonProcessingException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        String token = jwtTokenProvider.generateToken(authentication).toString();
        System.out.println("Token : "+token);
        return token;
    }
}
