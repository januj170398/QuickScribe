package com.anuj.QuickScribe.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthResponse {
    private String name;
    private String email;
    private String accessToken;
    private String refreshToken;
    private String message;
}
