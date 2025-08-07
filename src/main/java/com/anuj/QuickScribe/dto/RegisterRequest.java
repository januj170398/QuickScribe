package com.anuj.QuickScribe.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import com.anuj.QuickScribe.validation.ValidPassword;

@Schema(description = "User registration request containing user details and password")
public class RegisterRequest {

    @NotBlank(message = "Name is required")
    @Schema(description = "User's full name", example = "John Doe", required = true)
    private String name;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Schema(description = "User's email address", example = "john.doe@example.com", required = true)
    private String email;

    @NotBlank(message = "Password is required")
    @ValidPassword
    @Schema(description = "User's password (must meet security requirements)",
            example = "SecurePass123!", required = true, minLength = 8)
    private String password;

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
}
