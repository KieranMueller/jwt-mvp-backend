package com.kieran.notepad.controller;

import com.kieran.notepad.entity.User;
import com.kieran.notepad.model.AuthenticationResponse;
import com.kieran.notepad.model.LoginDetails;
import com.kieran.notepad.service.AuthService;
import com.kieran.notepad.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {

    private final AuthService authService;
    private final JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody User request) {
        log.info("Register request received: {}", request);
        return authService.register(request);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody User request) {
        log.info("Login request received: {}", request);
        return authService.authenticate(request);
    }

    @PostMapping("/validate")
    public ResponseEntity<Boolean> hasValidToken(@RequestBody LoginDetails details) {
        log.info("Validate token request received: {}", details);
        User user = new User();
        user.setUsername(details.getUsername());
        return ResponseEntity.ok(jwtService.isValid(details.getToken(), user));
    }
}
