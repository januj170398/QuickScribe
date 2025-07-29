package com.anuj.QuickScribe.repository;

import com.anuj.QuickScribe.model.RefreshToken;
import com.anuj.QuickScribe.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    @Modifying
    int deleteByUser(User user);

    // New methods for enhanced security
    @Modifying
    int deleteByExpiryDateBefore(Instant expiryDate);

    @Modifying
    void deleteByToken(String token);

    // Find tokens by user - FIXED: Added missing method
    List<RefreshToken> findByUser(User user);

    // Find tokens by user ordered by creation date (newest first) for cleanup
    List<RefreshToken> findByUserOrderByCreatedAtDesc(User user);

    // Count active tokens for a user
    long countByUserAndExpiryDateAfter(User user, Instant currentTime);
}
