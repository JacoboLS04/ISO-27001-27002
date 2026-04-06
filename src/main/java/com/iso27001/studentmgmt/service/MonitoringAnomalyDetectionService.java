package com.iso27001.studentmgmt.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class MonitoringAnomalyDetectionService {

    private final MonitoringMetricsService monitoringMetricsService;
    private final SecurityAuditService securityAuditService;
    private final Map<String, Instant> lastAlertByType = new ConcurrentHashMap<>();

    @Value("${app.monitoring.anomaly.enabled:true}")
    private boolean enabled;

    @Value("${app.monitoring.anomaly.cooldown-seconds:180}")
    private long cooldownSeconds;

    @Value("${app.monitoring.threshold.http401-5m:25}")
    private int http401Threshold;

    @Value("${app.monitoring.threshold.login-failed-10m:15}")
    private int loginFailedThreshold;

    @Value("${app.monitoring.threshold.frontend-errors-10m:20}")
    private int frontendErrorsThreshold;

    public MonitoringAnomalyDetectionService(MonitoringMetricsService monitoringMetricsService,
                                             SecurityAuditService securityAuditService) {
        this.monitoringMetricsService = monitoringMetricsService;
        this.securityAuditService = securityAuditService;
    }

    @Scheduled(fixedDelayString = "${app.monitoring.anomaly.scan-ms:30000}")
    public void detectAnomalies() {
        monitoringMetricsService.refreshDerivedGauges();

        if (!enabled) {
            return;
        }

        int http401Last5m = monitoringMetricsService.getRecentCount("HTTP_401", Duration.ofMinutes(5));
        int loginFailedLast10m = monitoringMetricsService.getRecentCount("LOGIN_FAILED", Duration.ofMinutes(10));
        int frontendErrorLast10m = monitoringMetricsService.getRecentCount("FRONTEND_JS_ERROR", Duration.ofMinutes(10))
                + monitoringMetricsService.getRecentCount("FRONTEND_UNHANDLED_REJECTION", Duration.ofMinutes(10))
                + monitoringMetricsService.getRecentCount("FRONTEND_CSP_VIOLATION", Duration.ofMinutes(10))
                + monitoringMetricsService.getRecentCount("FRONTEND_SCRIPT_INJECTION_SUSPECTED", Duration.ofMinutes(10))
                + monitoringMetricsService.getRecentCount("FRONTEND_API_FAILURE_SPIKE", Duration.ofMinutes(10));

        maybeAlert(
                "ANOMALY_401_SPIKE",
                http401Last5m > http401Threshold,
                "Potential brute-force activity detected",
                Map.of("recent401", http401Last5m, "threshold", http401Threshold, "window", "5m")
        );

        maybeAlert(
                "ANOMALY_LOGIN_FAILED_SPIKE",
                loginFailedLast10m > loginFailedThreshold,
                "Failed login burst detected",
                Map.of("recentLoginFailed", loginFailedLast10m, "threshold", loginFailedThreshold, "window", "10m")
        );

        maybeAlert(
                "ANOMALY_FRONTEND_ERRORS_SPIKE",
                frontendErrorLast10m > frontendErrorsThreshold,
                "Frontend anomaly burst detected",
                Map.of("recentFrontendErrors", frontendErrorLast10m, "threshold", frontendErrorsThreshold, "window", "10m")
        );
    }

    private void maybeAlert(String alertType,
                            boolean condition,
                            String description,
                            Map<String, Object> metadata) {
        if (!condition || isInCooldown(alertType)) {
            return;
        }

        monitoringMetricsService.incrementAnomalyAlert();
        securityAuditService.publish(alertType, "monitor", "ALERT", description, metadata);
        lastAlertByType.put(alertType, Instant.now());
    }

    private boolean isInCooldown(String alertType) {
        Instant lastAlert = lastAlertByType.get(alertType);
        return lastAlert != null && lastAlert.plusSeconds(cooldownSeconds).isAfter(Instant.now());
    }
}
