package com.anuj.QuickScribe.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens",
       indexes = {
           @Index(name = "idx_refresh_token", columnList = "token"),
           @Index(name = "idx_refresh_user_id", columnList = "user_id"),
           @Index(name = "idx_refresh_expiry", columnList = "expiryDate")
       },
       uniqueConstraints = {
           @UniqueConstraint(name = "uk_refresh_token", columnNames = {"token"})
       })
@Data
@ToString(exclude = {"user"})
@EqualsAndHashCode(exclude = {"user", "createdAt", "updatedAt"})
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false,
                foreignKey = @ForeignKey(name = "fk_refresh_token_user"))
    @NotNull(message = "User is required")
    private User user;

    @Column(nullable = false, unique = true, length = 255)
    @NotNull(message = "Token is required")
    private String token;

    @Column(nullable = false)
    @NotNull(message = "Expiry date is required")
    private LocalDateTime expiryDate;

    @Column(nullable = false)
    private boolean revoked = false;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiryDate);
    }

    public boolean isValid() {
        return !revoked && !isExpired();
    }
}