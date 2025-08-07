package com.anuj.QuickScribe.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@Schema(description = "Authentication response containing user details and JWT tokens")
public class AuthResponse {

    @Schema(description = "User's display name", example = "John Doe")
    private String name;

    @Schema(description = "User's email address", example = "john.doe@example.com")
    private String email;

    @Schema(description = "JWT access token for API authentication",
            example = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJqb2huLmRvZUBleGFtcGxlLmNvbSIsImlhdCI6MTYzOTQ4MzIwMCwiZXhwIjoxNjM5NTY5NjAwfQ.signature")
    private String accessToken;

    @Schema(description = "Refresh token for obtaining new access tokens",
            example = "550e8400-e29b-41d4-a716-446655440000")
    private String refreshToken;

    @Schema(description = "Response message indicating the result of the operation",
            example = "Login successful")
    private String message;
}
