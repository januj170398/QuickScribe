# 📚 QuickScribe Authentication System - Complete Code Guide

## 🎯 Overview

This guide explains every line of code in the QuickScribe authentication system, including JWT tokens, OAuth2, refresh tokens, multi-device support, and security features.

## 📁 Project Structure Deep Dive

```
QuickScribe/
├── 🔧 Configuration Files
│   ├── application.properties          # Main configuration
│   ├── application-dev.properties      # Development settings
│   └── application-prod.properties     # Production settings
├── 📝 DTOs (Data Transfer Objects)
│   ├── AuthResponse.java              # Authentication response format
│   ├── LoginRequest.java              # Login request validation
│   └── RegisterRequest.java           # Registration request validation
├── 🏛️ Models (Database Entities)
│   ├── User.java                      # User entity with OAuth2 support
│   ├── RefreshToken.java              # Refresh token entity
│   └── AuthProvider.java              # Authentication provider enum
├── 🛡️ Security Layer
│   ├── JwtTokenProvider.java          # JWT creation and validation
│   ├── JwtAuthenticationFilter.java   # Request filter for JWT
│   ├── JwtAuthenticationEntryPoint.java # Unauthorized request handler
│   ├── CustomUserDetailsService.java  # User loading service
│   ├── OAuth2AuthenticationSuccessHandler.java # OAuth2 success handler
│   └── SecurityConfig.java            # Main security configuration
├── 🔄 Services (Business Logic)
│   ├── RefreshTokenService.java       # Refresh token management
│   └── DeviceInfoService.java         # Device information extraction
├── 🌐 Controllers (API Endpoints)
│   └── AuthController.java            # Authentication endpoints
└── 🗄️ Repositories (Data Access)
    ├── UserRepository.java            # User database operations
    └── RefreshTokenRepository.java    # Refresh token database operations
```

---

## 🔧 Configuration Files Explained

### 📄 application.properties (Main Configuration)

```properties
# Application Identity
spring.application.name=QuickScribe
server.port=${PORT:8080}  # Uses environment variable or defaults to 8080

# Profile Selection - Determines which additional config to load
spring.profiles.active=dev  # Loads application-dev.properties

# Database Configuration - PostgreSQL connection
spring.datasource.url=${DATABASE_URL:jdbc:postgresql://localhost:5432/quickscribe}
spring.datasource.username=${DATABASE_USERNAME:postgres}
spring.datasource.password=${DATABASE_PASSWORD:admin}
spring.datasource.driver-class-name=org.postgresql.Driver

# JPA/Hibernate Configuration
spring.jpa.hibernate.ddl-auto=${DDL_AUTO:create-drop}  # Database schema management
# create-drop: Creates tables on startup, drops on shutdown (dev only)
# update: Updates existing schema (safer for prod)
# validate: Only validates schema (production)

spring.jpa.show-sql=${SHOW_SQL:false}  # Show SQL queries in logs
spring.jpa.open-in-view=false  # Prevent lazy loading issues
spring.jpa.properties.hibernate.format_sql=true  # Pretty print SQL
spring.jpa.properties.hibernate.use_sql_comments=true  # Add comments to SQL

# JWT Security Configuration
app.jwt.secret=${JWT_SECRET:QuickScribe2024SecureJWTSecretKeyForDevelopmentOnlyMustBeChanged32CharsMinimum!@#$%}
app.jwt.expiration=${JWT_EXPIRATION:86400}  # 24 hours in seconds
app.jwt.refresh-expiration=${JWT_REFRESH_EXPIRATION:604800}  # 7 days in seconds

# CORS Configuration - Cross-Origin Resource Sharing
app.cors.allowed-origins=${CORS_ALLOWED_ORIGINS:http://localhost:3000,http://localhost:8080}
app.cors.allowed-methods=${CORS_ALLOWED_METHODS:GET,POST,PUT,DELETE,OPTIONS,PATCH}
app.cors.allowed-headers=${CORS_ALLOWED_HEADERS:*}
app.cors.allow-credentials=${CORS_ALLOW_CREDENTIALS:true}

# Google OAuth2 Configuration
spring.security.oauth2.client.registration.google.client-id=${GOOGLE_CLIENT_ID:}
spring.security.oauth2.client.registration.google.client-secret=${GOOGLE_CLIENT_SECRET:}
spring.security.oauth2.client.registration.google.scope=profile,email
```

**Why Each Setting Matters:**

- **Environment Variables**: `${VAR:default}` syntax allows secure production deployment
- **Profile-based Config**: Different settings for dev/staging/production
- **Database Schema Management**: `ddl-auto` controls how database tables are managed
- **JWT Expiration**: Balances security (shorter) vs user experience (longer)
- **CORS**: Allows frontend applications to communicate with API

---

## 📝 DTOs (Data Transfer Objects)

### 🔐 LoginRequest.java - Request Validation

```java
package com.anuj.QuickScribe.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data  // Lombok: Generates getters, setters, toString, equals, hashCode
public class LoginRequest {
    @NotBlank(message = "Email is required")  // Validation: Field cannot be null/empty
    @Email(message = "Email should be valid")  // Validation: Must be valid email format
    private String email;

    @NotBlank(message = "Password is required")  // Validation: Password required
    private String password;
}
```

**How Validation Works:**
1. Client sends JSON: `{"email": "user@example.com", "password": "secret"}`
2. Spring converts JSON to LoginRequest object
3. `@Valid` annotation in controller triggers validation
4. If validation fails, returns 400 Bad Request with error message
5. If validation passes, authentication proceeds

### 📊 AuthResponse.java - Response Format

```java
package com.anuj.QuickScribe.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder  // Lombok: Enables builder pattern for object creation
@NoArgsConstructor  // Lombok: Creates no-args constructor
@AllArgsConstructor  // Lombok: Creates constructor with all fields
public class AuthResponse {
    private String accessToken;     // JWT token for API access
    private String refreshToken;    // Token to refresh expired access tokens
    @Builder.Default                // Lombok: Sets default value
    private String tokenType = "Bearer";  // Standard OAuth2 token type
    private String email;           // User's email address
    private String name;            // User's display name
}
```

**Usage Example:**
```java
// Building response using builder pattern
AuthResponse response = AuthResponse.builder()
    .accessToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    .refreshToken("550e8400-e29b-41d4-a716-446655440000")
    .email("user@example.com")
    .name("John Doe")
    .build();
```

---

## 🏛️ Models (Database Entities)

### 👤 User.java - User Entity with OAuth2 Support

```java
package com.anuj.QuickScribe.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity  // JPA: Marks this as a database entity
@Table(name = "users")  // JPA: Maps to 'users' table
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id  // JPA: Primary key
    @GeneratedValue(strategy = GenerationType.IDENTITY)  // Auto-increment ID
    private Long id;

    @Column(nullable = false)  // Database constraint: NOT NULL
    private String name;

    @Column(nullable = false, unique = true)  // Database constraint: NOT NULL + UNIQUE
    private String email;

    @Column  // Password can be null for OAuth2-only accounts
    private String password;

    @Enumerated(EnumType.STRING)  // Store enum as string in database
    @Column(nullable = false)
    private AuthProvider provider = AuthProvider.LOCAL;

    @Column(nullable = false)
    private Boolean enabled = true;

    // Business logic method - checks if user has local password
    public boolean hasLocalPassword() {
        return password != null && !password.trim().isEmpty();
    }
}
```

**Database Schema Generated:**
```sql
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,           -- Auto-increment ID
    name VARCHAR(255) NOT NULL,         -- User's display name
    email VARCHAR(255) NOT NULL UNIQUE, -- Email (unique constraint)
    password VARCHAR(255),              -- Encrypted password (nullable for OAuth2)
    provider VARCHAR(255) NOT NULL,     -- 'LOCAL' or 'GOOGLE'
    enabled BOOLEAN NOT NULL            -- Account status
);
```

### 🔄 RefreshToken.java - Multi-Device Token Support

```java
package com.anuj.QuickScribe.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "refresh_tokens")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)  // CRITICAL: Token value must be unique
    private String token;

    @Column(nullable = false)
    private Instant expiryDate;

    // CHANGED: ManyToOne allows multiple tokens per user (multi-device support)
    @ManyToOne(fetch = FetchType.LAZY)  // Lazy loading for performance
    @JoinColumn(name = "user_id", referencedColumnName = "id", nullable = false)
    private User user;

    @Column(name = "device_info")  // Device information for security tracking
    private String deviceInfo;

    @Column(name = "created_at")  // Creation timestamp
    private Instant createdAt;
}
```

**Database Schema Generated:**
```sql
CREATE TABLE refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(255) NOT NULL UNIQUE,  -- Globally unique token
    expiry_date TIMESTAMP NOT NULL,      -- When token expires
    user_id BIGINT NOT NULL,             -- Foreign key to users table
    device_info TEXT,                    -- Device tracking info
    created_at TIMESTAMP,                -- Creation timestamp
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Index for performance
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expiry ON refresh_tokens(expiry_date);
```

---

## 🛡️ Security Layer Deep Dive

### 🔑 JwtTokenProvider.java - JWT Creation and Validation

```java
package com.anuj.QuickScribe.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Component
@Slf4j
public class JwtTokenProvider {

    @Value("${app.jwt.secret}")  // Injected from application.properties
    private String jwtSecret;

    @Value("${app.jwt.expiration}")
    private int jwtExpirationInMs;

    // Creates cryptographically secure signing key
    private SecretKey getSigningKey() {
        // Security validation - ensures secret is strong enough
        if (jwtSecret == null || jwtSecret.length() < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 characters long for security");
        }
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());  // HMAC-SHA256 key
    }

    // Generate JWT from Spring Security Authentication object
    public String generateToken(Authentication authentication) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
        return generateTokenForUser(userPrincipal.getUsername());
    }

    // Generate JWT for specific user (used in OAuth2 and registration)
    public String generateTokenForUser(String username) {
        Instant now = Instant.now();
        Instant expiryDate = now.plus(jwtExpirationInMs, ChronoUnit.SECONDS);

        return Jwts.builder()
                .setSubject(username)           // JWT subject = user email
                .setIssuedAt(Date.from(now))    // When token was created
                .setExpiration(Date.from(expiryDate))  // When token expires
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)  // Signature algorithm
                .compact();  // Creates final JWT string
    }

    // Extract username from JWT token
    public String getUsernameFromJWT(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())  // Use same key for verification
                .build()
                .parseClaimsJws(token)          // Parse and verify signature
                .getBody();                     // Get claims

        return claims.getSubject();  // Return username from subject claim
    }

    // Validate JWT token integrity and expiration
    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(authToken);  // This throws exception if invalid
            return true;
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token");      // Malformed token structure
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token");      // Token past expiration time
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token");  // Unsupported algorithm/format
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty.");  // Empty token
        }
        return false;
    }
}
```

**JWT Token Structure:**
```
Header.Payload.Signature
```

**Example JWT Breakdown:**
```json
// Header (Base64 encoded)
{
  "alg": "HS256",
  "typ": "JWT"
}

// Payload (Base64 encoded)
{
  "sub": "user@example.com",      // Subject (username)
  "iat": 1643723400,              // Issued at (timestamp)
  "exp": 1643809800               // Expires at (timestamp)
}

// Signature (HMAC SHA256)
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

### 🛡️ JwtAuthenticationFilter.java - Request Processing

```java
package com.anuj.QuickScribe.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain filterChain) throws ServletException, IOException {
        try {
            // Step 1: Extract JWT from request
            String jwt = getJwtFromRequest(request);

            // Step 2: Validate JWT token
            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                // Step 3: Extract username from valid JWT
                String username = tokenProvider.getUsernameFromJWT(jwt);

                // Step 4: Load user details from database
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                
                // Step 5: Create authentication object
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                
                // Step 6: Set additional details (IP address, session ID, etc.)
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Step 7: Set authentication in security context
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            log.error("Could not set user authentication in security context", ex);
            // Don't throw exception - let request continue without authentication
        }

        // Step 8: Continue filter chain (proceed to next filter or controller)
        filterChain.doFilter(request, response);
    }

    // Extract JWT from Authorization header
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        // Expected format: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);  // Remove "Bearer " prefix
        }
        return null;
    }
}
```

**Filter Execution Flow:**
```
1. HTTP Request arrives
   ↓
2. JwtAuthenticationFilter.doFilterInternal()
   ↓
3. Extract "Authorization: Bearer <token>" header
   ↓
4. Validate JWT signature and expiration
   ↓
5. If valid: Load user from database
   ↓
6. Create Spring Security Authentication object
   ↓
7. Set authentication in SecurityContext
   ↓
8. Continue to next filter/controller
   ↓
9. Controller can access authenticated user via SecurityContext
```

---

## 🔄 Services (Business Logic)

### 🔄 RefreshTokenService.java - Multi-Device Token Management

```java
package com.anuj.QuickScribe.service;

import com.anuj.QuickScribe.exception.RefreshTokenExpiredException;
import com.anuj.QuickScribe.exception.UserNotFoundException;
import com.anuj.QuickScribe.model.RefreshToken;
import com.anuj.QuickScribe.model.User;
import com.anuj.QuickScribe.repository.RefreshTokenRepository;
import com.anuj.QuickScribe.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    @Value("${app.jwt.refresh-expiration:604800}")  // 7 days default
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    // Find refresh token by token string
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    // Create new refresh token (legacy method without device info)
    public RefreshToken createRefreshToken(String userEmail) {
        if (userEmail == null || userEmail.trim().isEmpty()) {
            throw new IllegalArgumentException("User email cannot be null or empty");
        }

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + userEmail));

        // Security enhancement: Limit tokens per user (max 5 devices)
        cleanupOldTokensForUser(userEmail, 5);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusSeconds(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());  // Generate random UUID
        refreshToken.setCreatedAt(Instant.now());

        refreshToken = refreshTokenRepository.save(refreshToken);
        log.info("Created refresh token for user: {}", userEmail);
        return refreshToken;
    }

    // Enhanced method with device info support
    public RefreshToken createRefreshTokenWithDeviceInfo(String userEmail, String deviceInfo) {
        if (userEmail == null || userEmail.trim().isEmpty()) {
            throw new IllegalArgumentException("User email cannot be null or empty");
        }

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + userEmail));

        // Security: Cleanup old tokens to prevent unlimited token creation
        cleanupOldTokensForUser(userEmail, 5);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusSeconds(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setCreatedAt(Instant.now());
        refreshToken.setDeviceInfo(deviceInfo);  // Track device for security

        refreshToken = refreshTokenRepository.save(refreshToken);
        log.info("Created refresh token for user: {} with device info: {}", userEmail, deviceInfo);
        return refreshToken;
    }

    // Verify token hasn't expired, delete if expired
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token == null) {
            throw new IllegalArgumentException("Refresh token cannot be null");
        }

        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);  // Remove expired token
            log.warn("Refresh token expired for user: {}", token.getUser().getEmail());
            throw new RefreshTokenExpiredException("Refresh token has expired. Please login again.");
        }
        return token;
    }

    // Security: Limit number of tokens per user
    @Transactional
    private void cleanupOldTokensForUser(String userEmail, int maxTokens) {
        Optional<User> userOptional = userRepository.findByEmail(userEmail);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            List<RefreshToken> userTokens = refreshTokenRepository.findByUser(user);
            
            if (userTokens.size() > maxTokens) {
                // Sort by creation date (oldest first) and delete excess tokens
                userTokens.sort(Comparator.comparing(RefreshToken::getCreatedAt));
                int tokensToDelete = userTokens.size() - maxTokens;
                
                for (int i = 0; i < tokensToDelete; i++) {
                    refreshTokenRepository.delete(userTokens.get(i));
                }
                
                log.info("Cleaned up old refresh tokens for user: {}. Deleted {} tokens.", 
                        userEmail, tokensToDelete);
            }
        }
    }

    // Delete all tokens for a user (logout from all devices)
    @Transactional
    public void deleteByUserEmail(String userEmail) {
        if (userEmail == null || userEmail.trim().isEmpty()) {
            throw new IllegalArgumentException("User email cannot be null or empty");
        }

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + userEmail));

        refreshTokenRepository.deleteByUser(user);
        log.info("Deleted all refresh tokens for user: {}", userEmail);
    }

    // Cleanup expired tokens (can be run as scheduled task)
    @Transactional
    public void deleteExpiredTokens() {
        int deletedCount = refreshTokenRepository.deleteByExpiryDateBefore(Instant.now());
        log.info("Cleaned up {} expired refresh tokens", deletedCount);
    }
}
```

**Multi-Device Security Flow:**
```
User Login from Device 1 (Laptop)
├── Create RefreshToken with device info: "Desktop - macOS - Chrome"
├── User now has 1 active token

User Login from Device 2 (Phone)  
├── Create RefreshToken with device info: "Mobile - iOS - Safari"
├── User now has 2 active tokens
├── Both devices work independently

User Login from Device 6 (6th device)
├── cleanupOldTokensForUser(email, 5) called
├── Find user's tokens: [token1, token2, token3, token4, token5]
├── Sort by creation date (oldest first)
├── Delete oldest token (token1 from Device 1)
├── Create new token for Device 6
├── User now has 5 active tokens (Devices 2,3,4,5,6)
```

---

## 🌐 Controllers (API Endpoints)

### 🔐 AuthController.java - Authentication Endpoints

```java
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
@RequestMapping("/api/auth")  // Base URL: /api/auth
@RequiredArgsConstructor  // Lombok: Generates constructor for final fields
@Slf4j
public class AuthController {

    // Dependency injection via constructor (immutable dependencies)
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final DeviceInfoService deviceInfoService;

    // POST /api/auth/login - User authentication endpoint
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
                                             HttpServletRequest request) {
        try {
            // Step 1: Extract device information for security tracking
            String deviceInfo = deviceInfoService.extractDeviceInfo(request);

            // Step 2: Authenticate user credentials
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),    // Username (email)
                            loginRequest.getPassword()  // Password (plaintext)
                    )
            );
            // AuthenticationManager will:
            // - Call CustomUserDetailsService.loadUserByUsername()
            // - Compare provided password with stored hash
            // - Throw BadCredentialsException if invalid

            // Step 3: Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Step 4: Generate JWT access token
            String jwt = tokenProvider.generateToken(authentication);

            // Step 5: Create refresh token with device tracking
            var refreshToken = refreshTokenService.createRefreshTokenWithDeviceInfo(
                loginRequest.getEmail(), deviceInfo);

            // Step 6: Load user details for response
            User user = userRepository.findByEmail(loginRequest.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Step 7: Log successful login with device info
            log.info("User login successful: {} from device: {}", loginRequest.getEmail(), deviceInfo);

            // Step 8: Return authentication response
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

    // POST /api/auth/register - User registration endpoint
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest,
                                         HttpServletRequest request) {
        try {
            // Step 1: Check if email already exists
            if (userRepository.existsByEmail(registerRequest.getEmail())) {
                return ResponseEntity.badRequest()
                        .body("Error: Email is already taken!");
            }

            // Step 2: Create new user entity
            User user = new User();
            user.setName(registerRequest.getName());
            user.setEmail(registerRequest.getEmail());
            // Hash password using BCrypt (configured in SecurityConfig)
            user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
            user.setProvider(AuthProvider.LOCAL);  // Local account (not OAuth2)
            user.setEnabled(true);  // Account is active

            // Step 3: Save user to database
            User savedUser = userRepository.save(user);

            // Step 4: Extract device info and generate tokens
            String deviceInfo = deviceInfoService.extractDeviceInfo(request);
            String jwt = tokenProvider.generateTokenForUser(savedUser.getEmail());
            var refreshToken = refreshTokenService.createRefreshTokenWithDeviceInfo(
                savedUser.getEmail(), deviceInfo);

            // Step 5: Log successful registration
            log.info("User registration successful: {} from device: {}", 
                    registerRequest.getEmail(), deviceInfo);

            // Step 6: Return tokens immediately (auto-login after registration)
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
```

**API Request/Response Examples:**

**Registration Request:**
```bash
POST /api/auth/register
Content-Type: application/json

{
    "name": "John Doe",
    "email": "john.doe@example.com", 
    "password": "SecurePassword123!"
}
```

**Registration Response:**
```json
{
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
    "tokenType": "Bearer",
    "email": "john.doe@example.com",
    "name": "John Doe"
}
```

**Login Request:**
```bash
POST /api/auth/login
Content-Type: application/json

{
    "email": "john.doe@example.com",
    "password": "SecurePassword123!"
}
```

---

## 🔄 Complete Authentication Flow

### 🔐 User Registration Flow

```
1. Frontend sends POST /api/auth/register
   ├── JSON: {name, email, password}
   ├── @Valid triggers validation (LoginRequest)
   ├── If validation fails → 400 Bad Request

2. AuthController.registerUser()
   ├── Check if email exists in database
   ├── If exists → 400 "Email already taken"
   ├── Create new User entity
   ├── Hash password with BCrypt
   ├── Set provider = LOCAL, enabled = true
   ├── Save user to database

3. Device Info Extraction
   ├── DeviceInfoService.extractDeviceInfo(request)
   ├── Parse User-Agent header
   ├── Detect: Device type, OS, Browser
   ├── Result: "Desktop - macOS - Chrome"

4. Token Generation
   ├── Generate JWT access token (24 hours)
   ├── Create refresh token (7 days) with device info
   ├── Store refresh token in database

5. Response
   ├── Return AuthResponse with tokens
   ├── Frontend stores tokens in localStorage
   ├── User is automatically logged in
```

### 🔑 User Login Flow

```
1. Frontend sends POST /api/auth/login
   ├── JSON: {email, password}
   ├── Headers: Content-Type: application/json

2. Spring Security Authentication
   ├── AuthenticationManager.authenticate()
   ├── Creates UsernamePasswordAuthenticationToken
   ├── Calls CustomUserDetailsService.loadUserByUsername()
   ├── Loads user from database by email
   ├── Compares password hash using BCrypt
   ├── If invalid → BadCredentialsException → 401

3. If Authentication Successful
   ├── Set authentication in SecurityContext
   ├── Extract device info from request
   ├── Generate new JWT access token
   ├── Create new refresh token with device info
   ├── Clean up old tokens (keep max 5 per user)

4. Response
   ├── Return AuthResponse with new tokens
   ├── Log successful login with device info
   ├── Frontend updates stored tokens
```

### 🌐 OAuth2 Google Login Flow

```
1. User clicks "Sign in with Google"
   ├── Browser redirects to /oauth2/authorization/google
   ├── Spring Security OAuth2 handles redirect
   ├── Redirects to Google OAuth2 authorization server

2. Google Authentication
   ├── User authenticates with Google
   ├── Google redirects back with authorization code
   ├── URL: /login/oauth2/code/google?code=<auth_code>

3. OAuth2AuthenticationSuccessHandler.onAuthenticationSuccess()
   ├── Spring Security exchanges code for tokens
   ├── Retrieves user info from Google API
   ├── Calls processOAuth2User()

4. processOAuth2User()
   ├── Extract email and name from Google user info
   ├── Check if user exists in database
   ├── If exists: Update user info if changed
   ├── If not exists: Create new user with provider=GOOGLE
   ├── Save user to database

5. Token Generation
   ├── Extract device info from request
   ├── Generate JWT access token
   ├── Create refresh token with device info
   ├── Build redirect URL with tokens

6. Redirect to Frontend
   ├── URL: /oauth2-test.html?token=<jwt>&refreshToken=<refresh>&user=<name>
   ├── Frontend JavaScript extracts tokens from URL
   ├── Stores tokens in localStorage
   ├── User is logged in
```

### 🔒 Protected Endpoint Access

```
1. Frontend makes API call to protected endpoint
   ├── GET /api/protected/user-info
   ├── Headers: Authorization: Bearer <jwt_token>

2. JwtAuthenticationFilter.doFilterInternal()
   ├── Extract JWT from Authorization header
   ├── Remove "Bearer " prefix
   ├── Validate JWT signature and expiration
   ├── Extract username from JWT subject

3. If JWT Valid
   ├── Load UserDetails from database
   ├── Create Authentication object
   ├── Set authentication in SecurityContext
   ├── Continue to controller

4. Controller Method
   ├── @PreAuthorize or method-level security
   ├── Access authenticated user via SecurityContext
   ├── Return protected data

5. If JWT Invalid/Expired
   ├── JwtAuthenticationFilter logs error
   ├── No authentication set in SecurityContext
   ├── Controller returns 401 Unauthorized
```

### 🔄 Token Refresh Flow

```
1. Access token expires (after 24 hours)
   ├── API calls return 401 Unauthorized
   ├── Frontend detects token expiration

2. Frontend calls refresh endpoint
   ├── POST /api/auth/refresh
   ├── Body: {"refreshToken": "<refresh_token>"}

3. RefreshTokenController.refreshToken()
   ├── Find refresh token in database
   ├── Verify token hasn't expired
   ├── If expired: Delete token, return 401
   ├── If valid: Generate new access token

4. Response
   ├── Return new access token
   ├── Frontend updates stored token
   ├── Retry original API call with new token
```

---

## 🗄️ Database Design

### 📊 Entity Relationships

```
users                    refresh_tokens
┌─────────────────┐     ┌──────────────────────┐
│ id (PK)         │◄────┤ user_id (FK)         │
│ name            │     │ id (PK)              │
│ email (UNIQUE)  │     │ token (UNIQUE)       │
│ password        │     │ expiry_date          │
│ provider        │     │ device_info          │
│ enabled         │     │ created_at           │
└─────────────────┘     └──────────────────────┘

Relationship: One User can have Many RefreshTokens (ManyToOne)
```

### 🔍 Database Queries

**Common Queries Generated by JPA:**

```sql
-- User Registration
INSERT INTO users (name, email, password, provider, enabled) 
VALUES (?, ?, ?, 'LOCAL', true);

-- User Login (load by email)
SELECT * FROM users WHERE email = ?;

-- Create Refresh Token
INSERT INTO refresh_tokens (token, expiry_date, user_id, device_info, created_at)
VALUES (?, ?, ?, ?, ?);

-- Find Refresh Token
SELECT * FROM refresh_tokens WHERE token = ?;

-- Cleanup Old Tokens
SELECT * FROM refresh_tokens WHERE user_id = ? ORDER BY created_at ASC;
DELETE FROM refresh_tokens WHERE id IN (?, ?, ?);

-- Delete Expired Tokens
DELETE FROM refresh_tokens WHERE expiry_date < NOW();
```

---

## 🛡️ Security Features

### 🔐 Password Security

```java
// BCrypt Configuration (in SecurityConfig)
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);  // Strength factor 12
}

// Password Hashing Process
String plainPassword = "userPassword123";
String hashedPassword = passwordEncoder.encode(plainPassword);
// Result: "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"

// Password Verification
boolean matches = passwordEncoder.matches(plainPassword, hashedPassword);
// Returns: true if password matches, false otherwise
```

### 🔑 JWT Security

```java
// JWT Security Features:
1. Cryptographic Signature (HMAC-SHA256)
   - Prevents token tampering
   - Verifies token authenticity

2. Expiration Time (24 hours)
   - Limits exposure window
   - Forces periodic re-authentication

3. Strong Secret Key (256-bit minimum)
   - Makes brute force attacks infeasible
   - Secret stored in environment variables

4. No Sensitive Data in Token
   - Only stores user email (subject)
   - No passwords or personal information
```

### 🛡️ Multi-Device Security

```java
// Device Tracking Benefits:
1. Security Monitoring
   - Track login patterns across devices
   - Detect suspicious activity (new device types)
   - Audit trail for security incidents

2. Token Management
   - Limit active tokens per user (5 devices)
   - Automatic cleanup of old tokens
   - Prevent token proliferation attacks

3. User Experience
   - Users can see active devices
   - Remote logout capabilities
   - Device-specific session management
```

---

## 🚀 Testing Your Application

### 📝 Manual Testing Steps

1. **Start Application:**
   ```bash
   ./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
   ```

2. **Test Health Endpoint:**
   ```bash
   curl http://localhost:8080/actuator/health
   # Expected: {"status":"UP"}
   ```

3. **Test Registration:**
   ```bash
   curl -X POST http://localhost:8080/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{"name":"Test User","email":"test@example.com","password":"password123"}'
   ```

4. **Test Login:**
   ```bash
   curl -X POST http://localhost:8080/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com","password":"password123"}'
   ```

5. **Test OAuth2:**
   - Open: http://localhost:8080/oauth2-test.html
   - Click "Sign in with Google"
   - Complete Google authentication

### 🐛 Common Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| 400 Bad Request | Missing Content-Type header | Add `-H "Content-Type: application/json"` |
| 401 Unauthorized | Invalid/expired JWT | Check token format and expiration |
| 403 Forbidden | Missing required permissions | Verify user roles and authorities |
| Database connection error | PostgreSQL not running | Start PostgreSQL service |
| OAuth2 redirect error | Incorrect redirect URI | Check Google Cloud Console settings |

---

## 🎯 Key Learning Points

### 🔄 Understanding the Complete Flow

1. **Configuration Layer**: Properties files control behavior across environments
2. **Security Layer**: JWT tokens, filters, and authentication managers work together
3. **Service Layer**: Business logic handles token management and user operations
4. **Controller Layer**: REST APIs provide clean interfaces for frontend applications
5. **Data Layer**: JPA repositories handle database operations with proper relationships

### 🛡️ Security Best Practices Implemented

1. **Password Security**: BCrypt hashing with strong salt rounds
2. **JWT Security**: Strong secrets, reasonable expiration, signature verification
3. **Multi-Device Support**: Token limits, device tracking, automatic cleanup
4. **Input Validation**: Bean validation prevents malformed requests
5. **Error Handling**: Proper exception handling without information leakage

### 🚀 Production Readiness

1. **Environment Configuration**: Separate dev/prod configs with environment variables
2. **Database Management**: Proper schema versioning and connection pooling
3. **Logging**: Structured logging for monitoring and debugging
4. **Security Headers**: CORS, session cookies, and other security configurations
5. **Scalability**: Stateless authentication suitable for horizontal scaling

This comprehensive guide covers every aspect of the QuickScribe authentication system. Each component works together to provide secure, scalable, and user-friendly authentication with modern features like OAuth2 integration and multi-device support.
