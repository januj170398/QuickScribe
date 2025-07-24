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
    }
