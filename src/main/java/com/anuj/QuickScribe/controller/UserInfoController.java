package com.anuj.QuickScribe.controller;

import com.anuj.QuickScribe.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserInfoController {
    private final JwtTokenProvider tokenProvider;

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@RequestHeader("Authorization") String authHeader) {
        String token = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }
        if (token == null || !tokenProvider.validateToken(token)) {
            return ResponseEntity.status(401).body("Invalid or missing token");
        }
        String email = tokenProvider.getUsernameFromToken(token);
        Map<String, Object> data = new HashMap<>();
        data.put("email", email);
        data.put("dummy", "This is some dummy data for user: " + email);
        return ResponseEntity.ok(data);
    }
}

