package com.example.spring_security_jwt_auth.service;


import com.example.spring_security_jwt_auth.jwt.JwtService;
import com.example.spring_security_jwt_auth.models.Role;
import com.example.spring_security_jwt_auth.models.User;
import com.example.spring_security_jwt_auth.repositories.UserRepository;
import com.example.spring_security_jwt_auth.request.AuthenticationRequest;
import com.example.spring_security_jwt_auth.request.RegisterRequest;
import com.example.spring_security_jwt_auth.response.AuthenticationResponse;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthenticationService(UserRepository repository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationResponse register(RegisterRequest request) {
         var user = User.builder()
                 .firstName(request.getFirstName())
                 .lastName(request.getLastName())
                 .email(request.getEmail())
                 .password(passwordEncoder.encode(request.getPassword()))
                 .role(Role.USER)
                 .build();
        repository.save(user);

        var jwtToken = jwtService.generateToken(user);

        return  new AuthenticationResponse(jwtToken);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();

        var jwtToken = jwtService.generateToken(user);

        return  new AuthenticationResponse(jwtToken);
    }
}
