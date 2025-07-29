package com.anuj.QuickScribe.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@Slf4j
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Value("${server.port:8080}")
    private String serverPort;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                      AuthenticationException exception) throws IOException, ServletException {

        // DETAILED LOGGING for debugging
        log.error("=== OAuth2 AUTHENTICATION FAILURE DEBUG ===");
        log.error("Request URI: {}", request.getRequestURI());
        log.error("Request URL: {}", request.getRequestURL());
        log.error("Query String: {}", request.getQueryString());
        log.error("Method: {}", request.getMethod());
        log.error("Session ID: {}", request.getSession(false) != null ? request.getSession().getId() : "No Session");
        log.error("Exception Type: {}", exception.getClass().getSimpleName());
        log.error("Exception Message: {}", exception.getMessage());
        log.error("Exception Stack Trace: ", exception);

        // Log all request headers
        log.error("Request Headers:");
        request.getHeaderNames().asIterator().forEachRemaining(headerName ->
            log.error("  {}: {}", headerName, request.getHeader(headerName)));

        // Log session attributes if session exists
        if (request.getSession(false) != null) {
            log.error("Session Attributes:");
            request.getSession().getAttributeNames().asIterator().forEachRemaining(attrName ->
                log.error("  {}: {}", attrName, request.getSession().getAttribute(attrName)));
        }

        // FIXED: Properly encode error message to avoid invalid characters in URL
        String errorMessage = exception.getMessage();
        if (errorMessage != null) {
            // Remove brackets and other special characters that cause HTTP parsing errors
            errorMessage = errorMessage.replaceAll("[\\[\\]\\(\\)]", "")
                                     .replaceAll("[^a-zA-Z0-9_\\-\\s]", "_");
        }

        String targetUrl = UriComponentsBuilder.fromUriString("http://localhost:" + serverPort + "/oauth2-test.html")
                .queryParam("error", "authentication_failed")
                .queryParam("details", errorMessage)
                .build()
                .toUriString();

        log.error("Redirecting to failure URL: {}", targetUrl);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
