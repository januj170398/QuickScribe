package com.anuj.QuickScribe.repository;

import com.anuj.QuickScribe.model.RefreshToken;
import com.anuj.QuickScribe.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByUserAndRevokedFalse(User user);

    List<RefreshToken> findByExpiryDateBefore(LocalDateTime dateTime);

    @Modifying
    @Transactional
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.user = :user AND rt.revoked = false")
    void revokeAllUserTokens(@Param("user") User user);

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :dateTime OR rt.revoked = true")
    void cleanupExpiredAndRevokedTokens(@Param("dateTime") LocalDateTime dateTime);

    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.user = :user AND rt.revoked = false AND rt.expiryDate > :now")
    long countActiveTokensByUser(@Param("user") User user, @Param("now") LocalDateTime now);

    void deleteByToken(String token);

    @Query("SELECT rt FROM RefreshToken rt JOIN FETCH rt.user WHERE rt.token = :token")
    Optional<RefreshToken> findByTokenWithUser(@Param("token") String token);
}