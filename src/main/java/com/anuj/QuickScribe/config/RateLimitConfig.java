package com.anuj.QuickScribe.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Configuration
@Slf4j
public class RateLimitConfig {

    @Value("${app.rate-limit.requests-per-minute:60}")
    private int requestsPerMinute;

    @Value("${app.rate-limit.burst-capacity:10}")
    private int burstCapacity;

    // Simple in-memory rate limiter for demo (use Redis in production)
    private final ConcurrentMap<String, RateLimitBucket> rateLimitBuckets = new ConcurrentHashMap<>();

    public static class RateLimitBucket {
        private final int maxTokens;
        private final Duration refillPeriod;
        private int tokens;
        private long lastRefillTime;

        public RateLimitBucket(int maxTokens, Duration refillPeriod) {
            this.maxTokens = maxTokens;
            this.refillPeriod = refillPeriod;
            this.tokens = maxTokens;
            this.lastRefillTime = System.currentTimeMillis();
        }

        public synchronized boolean tryConsume() {
            refill();
            if (tokens > 0) {
                tokens--;
                return true;
            }
            return false;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            long timePassed = now - lastRefillTime;

            if (timePassed >= refillPeriod.toMillis()) {
                tokens = maxTokens;
                lastRefillTime = now;
            }
        }
    }

    @Bean
    public RateLimitService rateLimitService() {
        return new RateLimitService();
    }

    public class RateLimitService {

        public boolean isAllowed(String clientId) {
            RateLimitBucket bucket = rateLimitBuckets.computeIfAbsent(
                clientId,
                k -> new RateLimitBucket(requestsPerMinute, Duration.ofMinutes(1))
            );

            return bucket.tryConsume();
        }

        public void cleanup() {
            // Remove old buckets periodically
            rateLimitBuckets.entrySet().removeIf(entry -> {
                RateLimitBucket bucket = entry.getValue();
                return System.currentTimeMillis() - bucket.lastRefillTime > Duration.ofHours(1).toMillis();
            });
        }
    }

    // Optional: Redis configuration for distributed rate limiting
    /*
    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory("localhost", 6379);
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new StringRedisSerializer());
        return template;
    }
    */
}
