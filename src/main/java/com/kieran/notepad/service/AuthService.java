package com.kieran.notepad.service;

import com.kieran.notepad.entity.User;
import com.kieran.notepad.model.AuthenticationResponse;
import com.kieran.notepad.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public ResponseEntity<AuthenticationResponse> register(User request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            AuthenticationResponse res = new AuthenticationResponse(null,
                    "Username " + request.getUsername() + " already exists");
            return new ResponseEntity<>(res, HttpStatus.BAD_REQUEST);
        }

        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        user = userRepository.save(user);
        String token = jwtService.generateToken(user);
        AuthenticationResponse res = new AuthenticationResponse(token, null);
        return new ResponseEntity<>(res, HttpStatus.OK);
    }

    public ResponseEntity<AuthenticationResponse> authenticate(User request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        User user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        String token = jwtService.generateToken(user);
        AuthenticationResponse res = new AuthenticationResponse(token, null);
        return new ResponseEntity<>(res, HttpStatus.OK);
    }
}
