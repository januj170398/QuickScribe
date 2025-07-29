package com.anuj.QuickScribe.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/debug")
@Slf4j
public class OAuth2DebugController {

    @GetMapping("/session")
    public ResponseEntity<?> getSessionInfo(HttpServletRequest request) {
        Map<String, Object> sessionInfo = new HashMap<>();

        HttpSession session = request.getSession(false);
        if (session != null) {
            sessionInfo.put("sessionId", session.getId());
            sessionInfo.put("creationTime", session.getCreationTime());
            sessionInfo.put("lastAccessedTime", session.getLastAccessedTime());
            sessionInfo.put("maxInactiveInterval", session.getMaxInactiveInterval());
            sessionInfo.put("isNew", session.isNew());

            // Log session attributes
            Map<String, Object> attributes = new HashMap<>();
            session.getAttributeNames().asIterator().forEachRemaining(name -> {
                Object value = session.getAttribute(name);
                attributes.put(name, value != null ? value.toString() : "null");
            });
            sessionInfo.put("attributes", attributes);
        } else {
            sessionInfo.put("message", "No session found");
        }

        sessionInfo.put("requestURI", request.getRequestURI());
        sessionInfo.put("cookies", request.getCookies() != null ? request.getCookies().length : 0);

        return ResponseEntity.ok(sessionInfo);
    }

    @GetMapping("/oauth2-status")
    public ResponseEntity<?> getOAuth2Status(HttpServletRequest request) {
        Map<String, Object> status = new HashMap<>();

        HttpSession session = request.getSession(false);
        if (session != null) {
            // Check for OAuth2 authorization request
            Object authRequest = session.getAttribute("oauth2_auth_request");
            status.put("hasAuthorizationRequest", authRequest != null);
            status.put("authRequestType", authRequest != null ? authRequest.getClass().getSimpleName() : "none");

            // Check for other OAuth2 related attributes
            session.getAttributeNames().asIterator().forEachRemaining(name -> {
                if (name.toLowerCase().contains("oauth2") || name.toLowerCase().contains("authorization")) {
                    status.put("attribute_" + name, "present");
                }
            });
        } else {
            status.put("error", "No session available for OAuth2 state");
        }

        return ResponseEntity.ok(status);
    }

    @GetMapping("/clear-session")
    public ResponseEntity<?> clearSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
            log.info("Session cleared for debugging");
            return ResponseEntity.ok(Map.of("message", "Session cleared successfully"));
        }
        return ResponseEntity.ok(Map.of("message", "No session to clear"));
    }
}
