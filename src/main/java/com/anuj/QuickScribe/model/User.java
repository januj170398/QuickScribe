package com.anuj.QuickScribe.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "users")
@Data // from Lombok
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    private String password;

    private String name;

    @Enumerated(EnumType.STRING)
    private AuthProvider provider; // To distinguish between local and social logins

    @Column(nullable = false)
    private boolean enabled = true;

    /**
     * Checks if this user has a local password (non-OAuth2 account)
     * @return true if user has a password, false for OAuth2-only accounts
     */
    public boolean hasLocalPassword() {
        return password != null && !password.isEmpty();
    }

    /**
     * Checks if this is an OAuth2-only account
     * @return true if user is OAuth2-only, false if has local password
     */
    public boolean isOAuth2Only() {
        return provider != null && provider != AuthProvider.LOCAL && !hasLocalPassword();
    }
}
