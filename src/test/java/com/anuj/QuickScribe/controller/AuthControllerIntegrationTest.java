package com.anuj.QuickScribe.controller;

import com.anuj.QuickScribe.dto.LoginRequest;
import com.anuj.QuickScribe.dto.RegisterRequest;
import com.anuj.QuickScribe.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Test
    void testRegister_Success() throws Exception {
        RegisterRequest request = new RegisterRequest();
        request.setEmail("integrationtest@example.com");
        request.setPassword("Test@1234");
        request.setName("Integration Test");

        ResultActions result = mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));

        result.andExpect(status().isCreated())
              .andExpect(jsonPath("$.accessToken").exists())
              .andExpect(jsonPath("$.refreshToken").exists());
    }

    @Test
    void testRegister_Conflict() throws Exception {
        // Register user first
        RegisterRequest request = new RegisterRequest();
        request.setEmail("integrationtest2@example.com");
        request.setPassword("Test@1234");
        request.setName("Integration Test");
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
        // Try to register again
        ResultActions result = mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
        result.andExpect(status().isConflict());
    }

    @Test
    void testLogin_InvalidCredentials() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setEmail("notfound@example.com");
        request.setPassword("wrongpassword");
        ResultActions result = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
        result.andExpect(status().isUnauthorized());
    }
}

