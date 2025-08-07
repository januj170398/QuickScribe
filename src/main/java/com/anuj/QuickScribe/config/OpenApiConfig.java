package com.anuj.QuickScribe.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Value("${server.port:8080}")
    private String serverPort;

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("QuickScribe API")
                        .version("1.0.0")
                        .description("""
                            ## QuickScribe - Note-Taking Application API
                            
                            A comprehensive REST API for a note-taking application with the following features:
                            
                            ### Features
                            - **User Authentication**: Local registration/login and OAuth2 integration with Google
                            - **JWT Token Management**: Secure access tokens with refresh token rotation
                            - **User Management**: Profile management and user information retrieval
                            - **Security**: Rate limiting, CORS protection, and comprehensive input validation
                            
                            ### Authentication
                            This API uses JWT (JSON Web Tokens) for authentication. To access protected endpoints:
                            
                            1. **Register** a new account or **login** with existing credentials
                            2. Use the returned `accessToken` in the Authorization header: `Bearer {token}`
                            3. Refresh tokens when they expire using the `/api/auth/refresh` endpoint
                            
                            ### Rate Limiting
                            API requests are rate-limited to prevent abuse. Check response headers for rate limit status.
                            
                            ### Error Handling
                            All API errors follow a consistent format with appropriate HTTP status codes and descriptive messages.
                            """)
                        .termsOfService("https://quickscribe.com/terms")
                        .contact(new Contact()
                                .name("QuickScribe Development Team")
                                .email("support@quickscribe.com")
                                .url("https://quickscribe.com/contact"))
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:" + serverPort)
                                .description("Local Development Server"),
                        new Server()
                                .url("https://api.quickscribe.com")
                                .description("Production Server")))
                .externalDocs(new ExternalDocumentation()
                        .description("QuickScribe Documentation")
                        .url("https://docs.quickscribe.com"))
                .addTagsItem(new Tag()
                        .name("Authentication API")
                        .description("User authentication, registration, and OAuth2 endpoints"))
                .addTagsItem(new Tag()
                        .name("Refresh Token API")
                        .description("JWT token refresh and revocation endpoints"))
                .addTagsItem(new Tag()
                        .name("User Info API")
                        .description("User profile and information management endpoints"))
                .addTagsItem(new Tag()
                        .name("OAuth2 Test API")
                        .description("Development endpoints for testing OAuth2 flows"))
                .addTagsItem(new Tag()
                        .name("Development")
                        .description("Development and testing utilities"))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("JWT token for API authentication. Format: Bearer {token}")
                        )
                        .addSecuritySchemes("oauth2",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.OAUTH2)
                                        .description("OAuth2 authentication with Google")
                        )
                );
    }

    @Bean
    public GroupedOpenApi authenticationApi() {
        return GroupedOpenApi.builder()
                .group("authentication")
                .displayName("Authentication & User Management")
                .pathsToMatch("/api/auth/**", "/api/user/**")
                .build();
    }

    @Bean
    public GroupedOpenApi developmentApi() {
        return GroupedOpenApi.builder()
                .group("development")
                .displayName("Development & Testing")
                .pathsToMatch("/api/auth/test/**")
                .build();
    }

    @Bean
    public GroupedOpenApi publicApi() {
        return GroupedOpenApi.builder()
                .group("public")
                .displayName("Public Endpoints")
                .pathsToMatch("/api/public/**", "/health/**")
                .build();
    }
}
