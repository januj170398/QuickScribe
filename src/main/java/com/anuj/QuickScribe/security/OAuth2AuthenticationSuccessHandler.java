package com.anuj.QuickScribe.security;

import com.anuj.QuickScribe.model.AuthProvider;
import com.anuj.QuickScribe.model.User;
import com.anuj.QuickScribe.repository.UserRepository;
import com.anuj.QuickScribe.service.RefreshTokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;

    @Value("${app.cors.allowed-origins:http://localhost:3000}")
    private String allowedOrigins;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                      Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                      Authentication authentication) {
        try {
            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
            User user = processOAuth2User(oAuth2User);

            // Generate JWT tokens
            String accessToken = tokenProvider.generateTokenForUser(user.getEmail());
            var refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

            // Set tokens as HTTP-only cookies instead of URL parameters for security
            setTokenCookies(response, accessToken, refreshToken.getToken());

            // Get the first allowed origin for redirect - remove sensitive data from URL
            String redirectUrl = allowedOrigins.split(",")[0];

            return UriComponentsBuilder.fromUriString(redirectUrl + "/auth/oauth2/redirect")
                    .queryParam("success", "true")
                    .build().toUriString();

        } catch (Exception ex) {
            log.error("Error processing OAuth2 authentication", ex);
            String redirectUrl = allowedOrigins.split(",")[0];
            return UriComponentsBuilder.fromUriString(redirectUrl + "/auth/oauth2/redirect")
                    .queryParam("error", "authentication_failed")
                    .build().toUriString();
        }
    }

    private void setTokenCookies(HttpServletResponse response, String accessToken, String refreshToken) {
        // Set access token cookie
        Cookie accessTokenCookie = new Cookie("accessToken", accessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false); // Set to true in production with HTTPS
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(24 * 60 * 60); // 24 hours
        response.addCookie(accessTokenCookie);

        // Set refresh token cookie
        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false); // Set to true in production with HTTPS
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
        response.addCookie(refreshTokenCookie);
    }

    private User processOAuth2User(OAuth2User oAuth2User) {
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(email);
        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();
            // Update user info if needed
            if (name != null && !name.equals(user.getName())) {
                user.setName(name);
                user = userRepository.save(user);
            }
            log.info("Existing user logged in via Google: {}", email);
        } else {
            // Create new user
            user = new User();
            user.setEmail(email);
            user.setName(name != null ? name : email.split("@")[0]);
            user.setProvider(AuthProvider.GOOGLE);
            user.setPassword(""); // No password for OAuth2 users
            user.setEnabled(true);
            user = userRepository.save(user);
            log.info("New user created via Google OAuth2: {}", email);
        }

        return user;
    }
}
