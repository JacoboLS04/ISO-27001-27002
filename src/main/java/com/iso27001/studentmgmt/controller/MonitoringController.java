package com.iso27001.studentmgmt.controller;

import com.iso27001.studentmgmt.dto.FrontendMonitoringEventRequest;
import com.iso27001.studentmgmt.service.MonitoringMetricsService;
import com.iso27001.studentmgmt.service.SecurityAuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/monitoring/frontend")
public class MonitoringController {

    private final SecurityAuditService securityAuditService;
    private final MonitoringMetricsService monitoringMetricsService;

    public MonitoringController(SecurityAuditService securityAuditService,
                                MonitoringMetricsService monitoringMetricsService) {
        this.securityAuditService = securityAuditService;
        this.monitoringMetricsService = monitoringMetricsService;
    }

    @PostMapping("/events")
    public ResponseEntity<Map<String, String>> ingestFrontendEvent(@Valid @RequestBody FrontendMonitoringEventRequest request,
                                                                    HttpServletRequest servletRequest) {
        monitoringMetricsService.incrementFrontendEvent(request.getEventType());
        securityAuditService.publish(
                "FRONTEND_" + sanitize(request.getEventType(), 40),
                "frontend-client",
                sanitize(request.getSeverity(), 16),
                sanitize(request.getMessage(), 220),
                Map.of(
                        "url", sanitize(request.getUrl(), 200),
                        "ip", sanitize(servletRequest.getRemoteAddr(), 64),
                        "userAgent", sanitize(request.getUserAgent(), 220),
                        "stack", sanitize(request.getStack(), 1200),
                        "timestamp", sanitize(request.getTimestamp(), 64)
                )
        );

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("status", "accepted"));
    }

    private String sanitize(String value, int maxLength) {
        if (value == null || value.isBlank()) {
            return "n/a";
        }
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }
}
