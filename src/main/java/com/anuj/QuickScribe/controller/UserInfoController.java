package com.anuj.QuickScribe.controller;

import com.anuj.QuickScribe.security.JwtTokenProvider;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "User Info API", description = "Endpoints for retrieving user information and profile data")
public class UserInfoController {
    private final JwtTokenProvider tokenProvider;

    @Operation(summary = "Get current user information",
               description = "Retrieves the authenticated user's profile information based on the JWT token.",
               security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User information retrieved successfully",
                    content = @Content(schema = @Schema(type = "object",
                                      example = "{\"email\": \"user@example.com\", \"dummy\": \"This is some dummy data for user: user@example.com\"}"))),
        @ApiResponse(responseCode = "401", description = "Invalid or missing token",
                    content = @Content(schema = @Schema(type = "string", example = "Invalid or missing token"))),
        @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(
            @Parameter(description = "Authorization header with Bearer token", required = true,
                      example = "Bearer eyJhbGciOiJIUzUxMiJ9...")
            @RequestHeader("Authorization") String authHeader) {
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
