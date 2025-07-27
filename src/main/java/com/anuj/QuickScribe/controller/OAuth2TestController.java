package com.anuj.QuickScribe.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth/test")
@Slf4j
public class OAuth2TestController {

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @GetMapping("/google-oauth2")
    public ResponseEntity<Map<String, Object>> getGoogleOAuth2Info() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Google OAuth2 Configuration");
        response.put("clientId", googleClientId);
        response.put("authorizationUrl", "http://localhost:8081/oauth2/authorize/google");
        response.put("redirectUri", "http://localhost:8081/login/oauth2/code/google");
        response.put("scope", "profile email");

        Map<String, String> instructions = new HashMap<>();
        instructions.put("step1", "Open browser and navigate to authorizationUrl");
        instructions.put("step2", "Complete Google authentication");
        instructions.put("step3", "You'll be redirected with JWT tokens");
        instructions.put("step4", "Use the JWT token for authenticated requests");

        response.put("instructions", instructions);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/oauth2/redirect")
    public ResponseEntity<Map<String, Object>> handleOAuth2Redirect(
            @RequestParam(required = false) String token,
            @RequestParam(required = false) String refreshToken,
            @RequestParam(required = false) String error) {

        Map<String, Object> response = new HashMap<>();

        if (error != null) {
            response.put("success", false);
            response.put("error", error);
            log.error("OAuth2 authentication failed: {}", error);
        } else if (token != null) {
            response.put("success", true);
            response.put("accessToken", token);
            response.put("refreshToken", refreshToken);
            response.put("message", "Google OAuth2 authentication successful");
            log.info("OAuth2 authentication successful");
        } else {
            response.put("success", false);
            response.put("error", "No token or error parameter received");
        }

        return ResponseEntity.ok(response);
    }
}
