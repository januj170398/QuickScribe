package com.anuj.QuickScribe.config;

import com.anuj.QuickScribe.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Configuration
@EnableScheduling
@RequiredArgsConstructor
@Slf4j
public class ScheduledTasks {

    private final RefreshTokenService refreshTokenService;

    /**
     * Cleanup expired refresh tokens every hour
     */
    @Scheduled(fixedRate = 3600000) // 1 hour in milliseconds
    public void cleanupExpiredTokens() {
        log.info("Starting scheduled cleanup of expired refresh tokens");
        try {
            refreshTokenService.cleanupExpiredTokens();
        } catch (Exception e) {
            log.error("Error during scheduled token cleanup: {}", e.getMessage());
        }
    }
}
