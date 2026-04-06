package com.iso27001.studentmgmt.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class SecurityAuditService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityAuditService.class);

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    @Value("${app.log.siem.enabled:false}")
    private boolean siemEnabled;

    @Value("${app.log.siem.endpoint:}")
    private String siemEndpoint;

    @Value("${app.log.siem.api-key:}")
    private String siemApiKey;

    @Value("${app.log.siem.hmac-secret:}")
    private String siemHmacSecret;

    public SecurityAuditService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    public void publish(String eventType, String username, String status, String details) {
        publish(eventType, username, status, details, Map.of());
    }

    public void publish(String eventType,
                        String username,
                        String status,
                        String details,
                        Map<String, Object> metadata) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("timestamp", Instant.now().toString());
        event.put("eventType", eventType);
        event.put("username", username == null ? "unknown" : username);
        event.put("status", status);
        event.put("details", details);
        event.put("metadata", metadata);

        logger.info("AUDIT_EVENT type='{}' username='{}' status='{}' details='{}'", eventType, username, status, details);

        if (!siemEnabled || siemEndpoint == null || siemEndpoint.isBlank()) {
            return;
        }

        try {
            String payload = objectMapper.writeValueAsString(event);
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(siemEndpoint))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload));

            if (siemApiKey != null && !siemApiKey.isBlank()) {
                requestBuilder.header("X-API-Key", siemApiKey);
            }

            if (siemHmacSecret != null && !siemHmacSecret.isBlank()) {
                requestBuilder.header("X-Audit-Signature", hmacSha256(payload, siemHmacSecret));
            }

            httpClient.sendAsync(requestBuilder.build(), HttpResponse.BodyHandlers.discarding())
                    .thenAccept(response -> {
                        if (response.statusCode() >= 400) {
                            logger.warn("SIEM_FORWARD_FAILED statusCode='{}' endpoint='{}'", response.statusCode(), siemEndpoint);
                        }
                    })
                    .exceptionally(ex -> {
                        logger.warn("SIEM_FORWARD_FAILED endpoint='{}' reason='{}'", siemEndpoint, ex.getMessage());
                        return null;
                    });

        } catch (JsonProcessingException e) {
            logger.warn("SIEM_FORWARD_FAILED reason='payload serialization error'");
        } catch (Exception e) {
            logger.warn("SIEM_FORWARD_FAILED endpoint='{}' reason='{}'", siemEndpoint, e.getMessage());
        }
    }

    private String hmacSha256(String data, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            logger.warn("SIEM_HMAC_FAILED reason='{}'", e.getMessage());
            return "";
        }
    }
}
