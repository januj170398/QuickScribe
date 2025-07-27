// src/main/java/com/anuj/QuickScribe/controller/AuthController.java
package com.anuj.QuickScribe.controller;

import com.anuj.QuickScribe.dto.AuthResponse;
import com.anuj.QuickScribe.dto.LoginRequest;
import com.anuj.QuickScribe.dto.RegisterRequest;
import com.anuj.QuickScribe.model.AuthProvider;
import com.anuj.QuickScribe.model.RefreshToken;
import com.anuj.QuickScribe.model.User;
import com.anuj.QuickScribe.repository.UserRepository;
import com.anuj.QuickScribe.security.JwtTokenProvider;
import com.anuj.QuickScribe.service.RefreshTokenService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Api(tags = "Authentication API", description = "Endpoints for user authentication and registration")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;

    private AuthResponse createAuthResponse(User user, String accessToken, String refreshToken, String message) {
        return AuthResponse.builder()
                .name(user != null ? user.getName() : null)
                .email(user != null ? user.getEmail() : null)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .message(message)
                .build();
    }

    private AuthResponse createErrorResponse(String message) {
        return AuthResponse.builder()
                .message(message)
                .build();
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedForHeader = request.getHeader("X-Forwarded-For");
        if (xForwardedForHeader == null) {
            return request.getRemoteAddr();
        } else {
            return xForwardedForHeader.split(",")[0];
        }
    }

    @ApiOperation(value = "Register a new user", notes = "Creates a new user account and returns JWT tokens.")
    @ApiResponses({
        @ApiResponse(code = 201, message = "Registration successful"),
        @ApiResponse(code = 409, message = "Email already registered"),
        @ApiResponse(code = 500, message = "Registration failed. Please try again.")
    })
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request,
                                               HttpServletRequest httpRequest) {
        try {
            String clientIp = getClientIpAddress(httpRequest);
            log.info("Registration attempt for email: {} from IP: {}", request.getEmail(), clientIp);

            // Check if user already exists
            Optional<User> existingUser = userRepository.findByEmail(request.getEmail());
            if (existingUser.isPresent()) {
                log.warn("Registration attempt with already registered email: {} from IP: {}",
                        request.getEmail(), clientIp);
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(createErrorResponse("Email already registered"));
            }

            // Create new user
            User user = new User();
            user.setEmail(request.getEmail().toLowerCase().trim());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setName(request.getName().trim());
            user.setProvider(AuthProvider.LOCAL);
            user.setEnabled(true); // In production, you might want email verification first

            user = userRepository.save(user);

            // Authenticate the new user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

            String accessToken = tokenProvider.generateToken(authentication);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

            log.info("User registered successfully: {} from IP: {}", user.getEmail(), clientIp);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(createAuthResponse(user, accessToken, refreshToken.getToken(), "Registration successful"));

        } catch (Exception e) {
            log.error("Registration failed for email: {} - {}", request.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Registration failed. Please try again."));
        }
    }

    @ApiOperation(value = "Login user", notes = "Authenticates a user and returns JWT tokens.")
    @ApiResponses({
        @ApiResponse(code = 200, message = "Login successful"),
        @ApiResponse(code = 401, message = "Invalid email or password"),
        @ApiResponse(code = 500, message = "Login failed. Please try again.")
    })
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request,
                                            HttpServletRequest httpRequest) {
        try {
            String clientIp = getClientIpAddress(httpRequest);
            log.info("Login attempt for email: {} from IP: {}", request.getEmail(), clientIp);

            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail().toLowerCase().trim(),
                            request.getPassword()
                    ));

            // Get user details
            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found after authentication"));

            // Generate tokens
            String accessToken = tokenProvider.generateToken(authentication);
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

            log.info("User logged in successfully: {} from IP: {}", user.getEmail(), clientIp);
            return ResponseEntity.ok(createAuthResponse(user, accessToken, refreshToken.getToken(), "Login successful"));

        } catch (BadCredentialsException e) {
            log.warn("Invalid credentials for email: {} from IP: {}", request.getEmail(), getClientIpAddress(httpRequest));
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse("Invalid email or password"));
        } catch (DisabledException e) {
            log.warn("Account disabled for email: {} from IP: {}", request.getEmail(), getClientIpAddress(httpRequest));
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse("Account is disabled"));
        } catch (LockedException e) {
            log.warn("Account locked for email: {} from IP: {}", request.getEmail(), getClientIpAddress(httpRequest));
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse("Account is locked"));
        } catch (AuthenticationException e) {
            log.error("Authentication failed for email: {} from IP: {} - {}",
                    request.getEmail(), getClientIpAddress(httpRequest), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(createErrorResponse("Authentication failed"));
        } catch (Exception e) {
            log.error("Login failed for email: {} from IP: {} - {}",
                    request.getEmail(), getClientIpAddress(httpRequest), e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Login failed. Please try again."));
        }
    }

    @ApiOperation(value = "Logout user", notes = "Logs out the user and revokes refresh tokens.")
    @ApiResponses({
        @ApiResponse(code = 200, message = "Logout successful"),
        @ApiResponse(code = 400, message = "Invalid token"),
        @ApiResponse(code = 500, message = "Logout failed")
    })
    @PostMapping("/logout")
    public ResponseEntity<AuthResponse> logout(@RequestHeader("Authorization") String authHeader,
                                             HttpServletRequest httpRequest) {
        try {
            String clientIp = getClientIpAddress(httpRequest);

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                String username = tokenProvider.getUsernameFromToken(token);

                // Revoke all refresh tokens for this user
                refreshTokenService.revokeAllUserTokens(username);

                log.info("User logged out successfully: {} from IP: {}", username, clientIp);
                return ResponseEntity.ok(createErrorResponse("Logout successful"));
            }

            return ResponseEntity.badRequest().body(createErrorResponse("Invalid token"));
        } catch (Exception e) {
            log.error("Logout failed from IP: {} - {}", getClientIpAddress(httpRequest), e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Logout failed"));
        }
    }

    @ApiOperation(value = "OAuth2 login success callback", notes = "Handles successful OAuth2 authentication.")
    @GetMapping("/oauth2/success")
    public ResponseEntity<AuthResponse> oauth2Success(@RequestParam String token,
                                                    @RequestParam String refreshToken,
                                                    HttpServletRequest httpRequest) {
        try {
            String clientIp = getClientIpAddress(httpRequest);
            String username = tokenProvider.getUsernameFromToken(token);

            User user = userRepository.findByEmail(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            log.info("OAuth2 login success for user: {} from IP: {}", user.getEmail(), clientIp);
            return ResponseEntity.ok(createAuthResponse(user, token, refreshToken, "OAuth2 login successful"));

        } catch (Exception e) {
            log.error("OAuth2 success handling failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("OAuth2 authentication processing failed"));
        }
    }

    @ApiOperation(value = "OAuth2 login failure callback", notes = "Handles failed OAuth2 authentication.")
    @GetMapping("/oauth2/failure")
    public ResponseEntity<AuthResponse> oauth2Failure(@RequestParam(required = false) String error,
                                                    @RequestParam(required = false) String message,
                                                    HttpServletRequest httpRequest) {
        String clientIp = getClientIpAddress(httpRequest);
        log.error("OAuth2 authentication failed from IP: {} - Error: {}, Message: {}",
                 clientIp, error, message);

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(createErrorResponse("OAuth2 authentication failed: " + (message != null ? message : error)));
    }

    @ApiOperation(value = "Test Google OAuth2 user creation", notes = "Test endpoint to simulate Google OAuth2 user creation for development")
    @PostMapping("/test/google-oauth2")
    public ResponseEntity<AuthResponse> testGoogleOAuth2(@RequestBody Map<String, String> googleUserData,
                                                        HttpServletRequest httpRequest) {
        try {
            String clientIp = getClientIpAddress(httpRequest);
            log.info("Testing Google OAuth2 user creation from IP: {}", clientIp);

            // Simulate Google user data
            String email = googleUserData.get("email");
            String name = googleUserData.get("name");
            String googleId = googleUserData.get("sub");

            if (email == null || email.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(createErrorResponse("Email is required for testing"));
            }

            // Check if user already exists
            Optional<User> existingUser = userRepository.findByEmail(email);
            User user;

            if (existingUser.isPresent()) {
                user = existingUser.get();
                log.info("Existing Google user found: {}", email);
            } else {
                // Create new Google user
                user = new User();
                user.setEmail(email);
                user.setName(name != null ? name : email.split("@")[0]);
                user.setProvider(AuthProvider.GOOGLE);
                user.setPassword(""); // No password for OAuth2 users
                user.setEnabled(true);
                user = userRepository.save(user);
                log.info("New Google user created for testing: {}", email);
            }

            // Generate tokens
            String accessToken = tokenProvider.generateTokenForUser(user.getEmail());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

            return ResponseEntity.ok(createAuthResponse(user, accessToken, refreshToken.getToken(), "Google OAuth2 test successful"));

        } catch (Exception e) {
            log.error("Google OAuth2 test failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Google OAuth2 test failed"));
        }
    }
}