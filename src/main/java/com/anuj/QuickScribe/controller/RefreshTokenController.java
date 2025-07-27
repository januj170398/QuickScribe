package com.anuj.QuickScribe.controller;

import com.anuj.QuickScribe.dto.AuthResponse;
import com.anuj.QuickScribe.model.RefreshToken;
import com.anuj.QuickScribe.model.User;
import com.anuj.QuickScribe.security.JwtTokenProvider;
import com.anuj.QuickScribe.service.RefreshTokenService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Api(tags = "Refresh Token API", description = "Endpoints for refreshing and revoking tokens")
public class RefreshTokenController {

    private final RefreshTokenService refreshTokenService;
    private final JwtTokenProvider tokenProvider;

    public static class RefreshTokenRequest {
        @NotBlank(message = "Refresh token is required")
        private String refreshToken;

        public String getRefreshToken() {
            return refreshToken;
        }

        public void setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedForHeader = request.getHeader("X-Forwarded-For");
        if (xForwardedForHeader == null) {
            return request.getRemoteAddr();
        } else {
            return xForwardedForHeader.split(",")[0];
        }
    }

    @ApiOperation(value = "Refresh JWT token", notes = "Generates a new access and refresh token using a valid refresh token.")
    @ApiResponses({
        @ApiResponse(code = 200, message = "Token refreshed successfully"),
        @ApiResponse(code = 401, message = "Invalid or expired refresh token"),
        @ApiResponse(code = 500, message = "Token refresh failed")
    })
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request,
                                                   HttpServletRequest httpRequest) {
        try {
            String clientIp = getClientIpAddress(httpRequest);
            String refreshTokenValue = request.getRefreshToken();

            log.info("Token refresh attempt from IP: {}", clientIp);

            // Validate refresh token
            if (!refreshTokenService.validateRefreshToken(refreshTokenValue)) {
                log.warn("Invalid refresh token used from IP: {}", clientIp);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(AuthResponse.builder()
                                .message("Invalid or expired refresh token")
                                .build());
            }

            // Get user from refresh token (use DTO to avoid lazy loading issues)
            Optional<com.anuj.QuickScribe.dto.UserDto> userOpt = refreshTokenService.getUserDtoFromRefreshToken(refreshTokenValue);
            if (userOpt.isEmpty()) {
                log.warn("User not found for refresh token from IP: {}", clientIp);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(AuthResponse.builder()
                                .message("Invalid refresh token")
                                .build());
            }

            com.anuj.QuickScribe.dto.UserDto user = userOpt.get();

            // Generate new access token
            String newAccessToken = tokenProvider.generateTokenForUser(user.getEmail());

            // Optionally rotate refresh token for better security
            RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user.getEmail());

            log.info("Token refreshed successfully for user: {} from IP: {}", user.getEmail(), clientIp);

            return ResponseEntity.ok(AuthResponse.builder()
                    .name(user.getName())
                    .email(user.getEmail())
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken.getToken())
                    .message("Token refreshed successfully")
                    .build());

        } catch (Exception e) {
            log.error("Token refresh failed from IP: {} - {}", getClientIpAddress(httpRequest), e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(AuthResponse.builder()
                            .message("Token refresh failed")
                            .build());
        }
    }

    @ApiOperation(value = "Revoke refresh token", notes = "Revokes a refresh token, making it unusable.")
    @ApiResponses({
        @ApiResponse(code = 200, message = "Token revoked successfully"),
        @ApiResponse(code = 500, message = "Token revocation failed")
    })
    @PostMapping("/revoke")
    public ResponseEntity<AuthResponse> revokeToken(@Valid @RequestBody RefreshTokenRequest request,
                                                  HttpServletRequest httpRequest) {
        try {
            String clientIp = getClientIpAddress(httpRequest);
            String refreshTokenValue = request.getRefreshToken();

            log.info("Token revocation attempt from IP: {}", clientIp);

            refreshTokenService.revokeRefreshToken(refreshTokenValue);

            log.info("Token revoked successfully from IP: {}", clientIp);
            return ResponseEntity.ok(AuthResponse.builder()
                    .message("Token revoked successfully")
                    .build());

        } catch (Exception e) {
            log.error("Token revocation failed from IP: {} - {}", getClientIpAddress(httpRequest), e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(AuthResponse.builder()
                            .message("Token revocation failed")
                            .build());
        }
    }
}