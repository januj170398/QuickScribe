package com.anuj.QuickScribe.service;

import com.anuj.QuickScribe.model.RefreshToken;
import com.anuj.QuickScribe.model.User;
import com.anuj.QuickScribe.repository.RefreshTokenRepository;
import com.anuj.QuickScribe.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${refresh.token.expiry.ms:604800000}") // 7 days default
    private long refreshTokenExpiryMs;

    /**
     * Creates a new refresh token for the specified user
     */
    @Transactional
    public RefreshToken createRefreshToken(String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("User not found: " + userEmail));

        // Revoke existing refresh tokens for security (optional - you might want to allow multiple devices)
        revokeAllUserTokens(userEmail);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(generateSecureToken());
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(LocalDateTime.now().plusSeconds(refreshTokenExpiryMs / 1000));
        refreshToken.setRevoked(false);

        RefreshToken savedToken = refreshTokenRepository.save(refreshToken);
        log.info("Created refresh token for user: {}", userEmail);
        return savedToken;
    }

    /**
     * Generates a cryptographically secure random token
     */
    private String generateSecureToken() {
        byte[] tokenBytes = new byte[32]; // 256 bits
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    /**
     * Finds a refresh token by its value
     */
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    /**
     * Validates a refresh token
     */
    public boolean validateRefreshToken(String token) {
        try {
            Optional<RefreshToken> refreshTokenOpt = refreshTokenRepository.findByToken(token);

            if (refreshTokenOpt.isEmpty()) {
                log.warn("Refresh token not found: {}", token.substring(0, Math.min(token.length(), 10)) + "...");
                return false;
            }

            RefreshToken refreshToken = refreshTokenOpt.get();
            boolean isValid = refreshToken.isValid();

            if (!isValid) {
                log.warn("Invalid refresh token used: {} - revoked: {}, expired: {}",
                        token.substring(0, Math.min(token.length(), 10)) + "...",
                        refreshToken.isRevoked(),
                        refreshToken.isExpired());
            }

            return isValid;
        } catch (Exception e) {
            log.error("Error validating refresh token: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Revokes a specific refresh token
     */
    @Transactional
    public void revokeRefreshToken(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(refreshToken -> {
            refreshToken.setRevoked(true);
            refreshTokenRepository.save(refreshToken);
            log.info("Revoked refresh token: {}", token.substring(0, Math.min(token.length(), 10)) + "...");
        });
    }

    /**
     * Revokes all refresh tokens for a specific user
     */
    @Transactional
    public void revokeAllUserTokens(String userEmail) {
        try {
            User user = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new RuntimeException("User not found: " + userEmail));

            List<RefreshToken> userTokens = refreshTokenRepository.findByUserAndRevokedFalse(user);
            userTokens.forEach(token -> {
                token.setRevoked(true);
                refreshTokenRepository.save(token);
            });

            if (!userTokens.isEmpty()) {
                log.info("Revoked {} refresh tokens for user: {}", userTokens.size(), userEmail);
            }
        } catch (Exception e) {
            log.error("Error revoking tokens for user {}: {}", userEmail, e.getMessage());
        }
    }

    /**
     * Cleans up expired tokens (should be scheduled)
     */
    @Transactional
    public void cleanupExpiredTokens() {
        try {
            LocalDateTime now = LocalDateTime.now();
            List<RefreshToken> expiredTokens = refreshTokenRepository.findByExpiryDateBefore(now);

            if (!expiredTokens.isEmpty()) {
                refreshTokenRepository.deleteAll(expiredTokens);
                log.info("Cleaned up {} expired refresh tokens", expiredTokens.size());
            }
        } catch (Exception e) {
            log.error("Error during token cleanup: {}", e.getMessage());
        }
    }

    /**
     * Gets user from refresh token
     */
    public Optional<User> getUserFromRefreshToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .filter(RefreshToken::isValid)
                .map(RefreshToken::getUser);
    }

    /**
     * Gets user DTO from refresh token (eagerly fetches user)
     */
    @Transactional(readOnly = true)
    public Optional<com.anuj.QuickScribe.dto.UserDto> getUserDtoFromRefreshToken(String token) {
        return refreshTokenRepository.findByTokenWithUser(token)
                .filter(RefreshToken::isValid)
                .map(rt -> {
                    User user = rt.getUser();
                    return new com.anuj.QuickScribe.dto.UserDto(user.getName(), user.getEmail());
                });
    }
}