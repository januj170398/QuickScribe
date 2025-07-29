package com.anuj.QuickScribe.controller;

import com.anuj.QuickScribe.dto.AuthResponse;
import com.anuj.QuickScribe.dto.LoginRequest;
import com.anuj.QuickScribe.dto.RegisterRequest;
import com.anuj.QuickScribe.model.AuthProvider;
import com.anuj.QuickScribe.model.User;
import com.anuj.QuickScribe.repository.UserRepository;
import com.anuj.QuickScribe.security.JwtTokenProvider;
import com.anuj.QuickScribe.service.DeviceInfoService;
import com.anuj.QuickScribe.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
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
    private final DeviceInfoService deviceInfoService;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
                                             HttpServletRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Extract device info from request
            String deviceInfo = deviceInfoService.extractDeviceInfo(request);

            String jwt = tokenProvider.generateToken(authentication);
            var refreshToken = refreshTokenService.createRefreshTokenWithDeviceInfo(loginRequest.getEmail(), deviceInfo);

            User user = userRepository.findByEmail(loginRequest.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Log login with device info
            log.info("User login successful: {} from device: {}", loginRequest.getEmail(), deviceInfo);

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
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest,
                                         HttpServletRequest request) {
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

            // Extract device info from request
            String deviceInfo = deviceInfoService.extractDeviceInfo(request);

            // Generate JWT token with device info
            String jwt = tokenProvider.generateTokenForUser(savedUser.getEmail());
            var refreshToken = refreshTokenService.createRefreshTokenWithDeviceInfo(savedUser.getEmail(), deviceInfo);

            // Log registration with device info
            log.info("User registration successful: {} from device: {}", registerRequest.getEmail(), deviceInfo);

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
