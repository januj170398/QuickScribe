package com.anuj.QuickScribe.controller;

import com.anuj.QuickScribe.dto.AuthResponse;
import com.anuj.QuickScribe.dto.LoginRequest;
import com.anuj.QuickScribe.dto.RegisterRequest;
import com.anuj.QuickScribe.model.AuthProvider;
import com.anuj.QuickScribe.model.User;
import com.anuj.QuickScribe.repository.UserRepository;
import com.anuj.QuickScribe.security.JwtTokenProvider;
import com.anuj.QuickScribe.service.RefreshTokenService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String jwt = tokenProvider.generateToken(authentication);
            var refreshToken = refreshTokenService.createRefreshToken(loginRequest.getEmail());

            User user = userRepository.findByEmail(loginRequest.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            return ResponseEntity.ok(AuthResponse.builder()
                    .accessToken(jwt)
                    .refreshToken(refreshToken.getToken())
                    .email(user.getEmail())
                    .name(user.getName())
                    .build());

        } catch (Exception e) {
            log.error("Authentication failed for user: {}", loginRequest.getEmail(), e);
            return ResponseEntity.badRequest()
                    .body("Login failed: " + e.getMessage());
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
            if (userRepository.existsByEmail(registerRequest.getEmail())) {
                return ResponseEntity.badRequest()
                        .body("Error: Email is already taken!");
            }

            // Create new user
            User user = new User();
            user.setName(registerRequest.getName());
            user.setEmail(registerRequest.getEmail());
            user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
            user.setProvider(AuthProvider.LOCAL);
            user.setEnabled(true);

            User savedUser = userRepository.save(user);

            // Generate JWT token
            String jwt = tokenProvider.generateTokenForUser(savedUser.getEmail());
            var refreshToken = refreshTokenService.createRefreshToken(savedUser.getEmail());

            return ResponseEntity.ok(AuthResponse.builder()
                    .accessToken(jwt)
                    .refreshToken(refreshToken.getToken())
                    .email(savedUser.getEmail())
                    .name(savedUser.getName())
                    .build());

        } catch (Exception e) {
            log.error("Registration failed for user: {}", registerRequest.getEmail(), e);
            return ResponseEntity.badRequest()
                    .body("Registration failed: " + e.getMessage());
        }
    }
}
