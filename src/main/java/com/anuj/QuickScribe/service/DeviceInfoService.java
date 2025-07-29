package com.anuj.QuickScribe.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@Slf4j
public class DeviceInfoService {

    /**
     * Extract essential device information for security purposes
     * Keeps it simple but useful for tracking
     */
    public String extractDeviceInfo(HttpServletRequest request) {
        if (request == null) {
            return "Unknown Device";
        }

        String userAgent = request.getHeader("User-Agent");
        if (!StringUtils.hasText(userAgent)) {
            return "Unknown Device";
        }

        // Simple device type detection
        String deviceType = getDeviceType(userAgent);
        String browser = getSimpleBrowser(userAgent);
        String os = getSimpleOS(userAgent);

        // Create concise device info
        return String.format("%s - %s - %s", deviceType, os, browser);
    }

    /**
     * Generate a simple device fingerprint for security
     */
    public String generateDeviceFingerprint(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }

        String userAgent = request.getHeader("User-Agent");
        String acceptLanguage = request.getHeader("Accept-Language");

        StringBuilder fingerprint = new StringBuilder();
        fingerprint.append(getDeviceType(userAgent));
        fingerprint.append("_").append(getSimpleOS(userAgent));
        fingerprint.append("_").append(getSimpleBrowser(userAgent));

        if (StringUtils.hasText(acceptLanguage) && acceptLanguage.length() >= 2) {
            fingerprint.append("_").append(acceptLanguage.substring(0, 2));
        }

        return fingerprint.toString().toLowerCase().replaceAll("[^a-z0-9_]", "");
    }

    /**
     * Get user-friendly description for display
     */
    public String getFriendlyDeviceDescription(String deviceInfo) {
        if (!StringUtils.hasText(deviceInfo)) {
            return "Unknown Device";
        }

        // Convert "Mobile - iOS - Safari" to "Mobile iOS Safari"
        return deviceInfo.replace(" - ", " ");
    }

    private String getDeviceType(String userAgent) {
        if (!StringUtils.hasText(userAgent)) {
            return "Unknown";
        }

        userAgent = userAgent.toLowerCase();

        if (userAgent.contains("mobile") || userAgent.contains("android") || userAgent.contains("iphone")) {
            return "Mobile";
        }
        if (userAgent.contains("tablet") || userAgent.contains("ipad")) {
            return "Tablet";
        }

        return "Desktop";
    }

    private String getSimpleOS(String userAgent) {
        if (!StringUtils.hasText(userAgent)) {
            return "Unknown";
        }

        userAgent = userAgent.toLowerCase();

        if (userAgent.contains("windows")) return "Windows";
        if (userAgent.contains("mac")) return "macOS";
        if (userAgent.contains("android")) return "Android";
        if (userAgent.contains("iphone") || userAgent.contains("ipad") || userAgent.contains("ios")) return "iOS";
        if (userAgent.contains("linux")) return "Linux";

        return "Unknown";
    }

    private String getSimpleBrowser(String userAgent) {
        if (!StringUtils.hasText(userAgent)) {
            return "Unknown";
        }

        userAgent = userAgent.toLowerCase();

        // Order matters - check more specific first
        if (userAgent.contains("edg")) return "Edge";
        if (userAgent.contains("chrome")) return "Chrome";
        if (userAgent.contains("firefox")) return "Firefox";
        if (userAgent.contains("safari")) return "Safari";
        if (userAgent.contains("opera")) return "Opera";

        return "Unknown";
    }
}
