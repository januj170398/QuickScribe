package com.anuj.QuickScribe.controller;

import com.anuj.QuickScribe.model.User;
import com.anuj.QuickScribe.repository.UserRepository;
import com.anuj.QuickScribe.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/protected")
public class TestController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/user-info")
    public ResponseEntity<?> getUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername()).orElse(null);

        if (user == null) {
            return ResponseEntity.status(404).body("User not found");
        }

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("id", user.getId());
        userInfo.put("email", user.getEmail());
        userInfo.put("name", user.getName());
        userInfo.put("provider", user.getProvider().toString());
        userInfo.put("enabled", user.isEnabled());

        return ResponseEntity.ok(userInfo);
    }

    @GetMapping("/status")
    public ResponseEntity<?> getStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "authenticated");
        status.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(status);
    }
}
