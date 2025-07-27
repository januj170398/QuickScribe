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
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    @Value("${app.jwt.refresh-expiration:604800}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createRefreshToken(String userEmail) {
        if (userEmail == null || userEmail.trim().isEmpty()) {
            throw new IllegalArgumentException("User email cannot be null or empty");
        }

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + userEmail));

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusSeconds(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());

        refreshToken = refreshTokenRepository.save(refreshToken);
        log.info("Created refresh token for user: {}", userEmail);
        return refreshToken;
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token == null) {
            throw new IllegalArgumentException("Refresh token cannot be null");
        }

        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            log.warn("Refresh token expired for user: {}", token.getUser().getEmail());
            throw new RefreshTokenExpiredException("Refresh token has expired. Please login again.");
        }
        return token;
    }

    @Transactional
    public int deleteByUserId(Long userId) {
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + userId));

        int deletedCount = refreshTokenRepository.deleteByUser(user);
        log.info("Deleted {} refresh tokens for user ID: {}", deletedCount, userId);
        return deletedCount;
    }

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
}
