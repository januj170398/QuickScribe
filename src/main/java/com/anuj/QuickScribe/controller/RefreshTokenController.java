package com.anuj.QuickScribe.controller;

import com.anuj.QuickScribe.dto.AuthResponse;
import com.anuj.QuickScribe.model.RefreshToken;
import com.anuj.QuickScribe.security.JwtTokenProvider;
import com.anuj.QuickScribe.service.RefreshTokenService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class RefreshTokenController {

    private final RefreshTokenService refreshTokenService;
    private final JwtTokenProvider tokenProvider;

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = tokenProvider.generateTokenForUser(user.getEmail());
                    return ResponseEntity.ok(AuthResponse.builder()
                            .accessToken(token)
                            .refreshToken(requestRefreshToken)
                            .email(user.getEmail())
                            .name(user.getName())
                            .build());
                })
                .orElseThrow(() -> new RuntimeException("Refresh token is not in database!"));
    }

    @Data
    public static class RefreshTokenRequest {
        private String refreshToken;
    }
}
