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
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Authentication API", description = "Endpoints for user authentication and registration")
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

    @Operation(summary = "Register a new user",
               description = "Creates a new user account with email and password, returns JWT tokens upon successful registration.",
               requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                   description = "User registration details",
                   required = true,
                   content = @Content(schema = @Schema(implementation = RegisterRequest.class))
               ))
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Registration successful",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "409", description = "Email already registered",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid input data",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "500", description = "Registration failed. Please try again.",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class)))
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

    @Operation(summary = "Login user",
               description = "Authenticates a user with email and password, returns JWT tokens upon successful authentication.",
               requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                   description = "User login credentials",
                   required = true,
                   content = @Content(schema = @Schema(implementation = LoginRequest.class))
               ))
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Login successful",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "401", description = "Invalid email or password",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid input data",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "500", description = "Login failed. Please try again.",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class)))
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

    @Operation(summary = "Logout user",
               description = "Logs out the user and revokes all refresh tokens associated with the user.",
               security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Logout successful",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "400", description = "Invalid token",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "500", description = "Logout failed",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class)))
    })
    @PostMapping("/logout")
    public ResponseEntity<AuthResponse> logout(
            @Parameter(description = "Authorization header with Bearer token", required = true)
            @RequestHeader("Authorization") String authHeader,
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

    @Operation(summary = "OAuth2 login success callback",
               description = "Handles successful OAuth2 authentication and returns JWT tokens.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "OAuth2 login successful",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
        @ApiResponse(responseCode = "500", description = "OAuth2 authentication processing failed",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class)))
    })
    @GetMapping("/oauth2/success")
    public ResponseEntity<AuthResponse> oauth2Success(
            @Parameter(description = "JWT access token", required = true) @RequestParam String token,
            @Parameter(description = "Refresh token", required = true) @RequestParam String refreshToken,
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

    @Operation(summary = "OAuth2 login failure callback",
               description = "Handles failed OAuth2 authentication.")
    @ApiResponses({
        @ApiResponse(responseCode = "401", description = "OAuth2 authentication failed",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class)))
    })
    @GetMapping("/oauth2/failure")
    public ResponseEntity<AuthResponse> oauth2Failure(
            @Parameter(description = "Error code") @RequestParam(required = false) String error,
            @Parameter(description = "Error message") @RequestParam(required = false) String message,
            HttpServletRequest httpRequest) {
        String clientIp = getClientIpAddress(httpRequest);
        log.error("OAuth2 authentication failed from IP: {} - Error: {}, Message: {}",
                 clientIp, error, message);

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(createErrorResponse("OAuth2 authentication failed: " + (message != null ? message : error)));
    }
}
