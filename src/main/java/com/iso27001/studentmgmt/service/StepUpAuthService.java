package com.iso27001.studentmgmt.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class StepUpAuthService {

    private static final Logger logger = LoggerFactory.getLogger(StepUpAuthService.class);

    private final SecureRandom secureRandom = new SecureRandom();
    private final SecurityAuditService securityAuditService;

    public StepUpAuthService(SecurityAuditService securityAuditService) {
        this.securityAuditService = securityAuditService;
    }

    @Value("${app.auth.step-up-ttl-seconds:300}")
    private long stepUpTtlSeconds;

    private final Map<String, StepUpTokenData> tokenStore = new ConcurrentHashMap<>();

    public StepUpToken issueToken(String username) {
        byte[] randomBytes = new byte[24];
        secureRandom.nextBytes(randomBytes);

        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        Instant expiresAt = Instant.now().plusSeconds(stepUpTtlSeconds);

        tokenStore.put(token, new StepUpTokenData(username, expiresAt));
        logger.info("STEP_UP_ISSUED username='{}' expiresAt='{}'", username, expiresAt);
        securityAuditService.publish("STEP_UP", username, "SUCCESS", "Step-up token issued");

        return new StepUpToken(token, expiresAt);
    }

    public boolean consumeToken(String username, String token) {
        if (token == null || token.isBlank()) {
            return false;
        }

        StepUpTokenData data = tokenStore.remove(token);
        if (data == null) {
            logger.warn("STEP_UP_INVALID username='{}' reason='Token not found'", username);
            securityAuditService.publish("STEP_UP", username, "FAILED", "Token not found");
            return false;
        }

        if (!data.username.equals(username)) {
            logger.warn("STEP_UP_INVALID username='{}' reason='Username mismatch'", username);
            securityAuditService.publish("STEP_UP", username, "FAILED", "Token username mismatch");
            return false;
        }

        if (data.expiresAt.isBefore(Instant.now())) {
            logger.warn("STEP_UP_EXPIRED username='{}'", username);
            securityAuditService.publish("STEP_UP", username, "FAILED", "Token expired");
            return false;
        }

        logger.info("STEP_UP_CONSUMED username='{}'", username);
        securityAuditService.publish("STEP_UP", username, "SUCCESS", "Step-up token consumed");
        return true;
    }

    public static class StepUpToken {
        private final String token;
        private final Instant expiresAt;

        public StepUpToken(String token, Instant expiresAt) {
            this.token = token;
            this.expiresAt = expiresAt;
        }

        public String getToken() {
            return token;
        }

        public String getExpiresAtIso() {
            return DateTimeFormatter.ISO_INSTANT.format(expiresAt);
        }
    }

    private static class StepUpTokenData {
        private final String username;
        private final Instant expiresAt;

        private StepUpTokenData(String username, Instant expiresAt) {
            this.username = username;
            this.expiresAt = expiresAt;
        }
    }
}
