package com.iso27001.studentmgmt.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class MonitoringMetricsService {

    private final Counter loginSuccessCounter;
    private final Counter loginFailedCounter;
    private final Counter loginLockedCounter;
    private final Counter http401Counter;
    private final Counter frontendJsErrorCounter;
    private final Counter frontendUnhandledRejectionCounter;
    private final Counter frontendCspViolationCounter;
    private final Counter frontendScriptInjectionCounter;
    private final Counter frontendApiFailureSpikeCounter;
    private final Counter anomalyAlertCounter;

    private final Map<String, Deque<Instant>> rollingEventWindows = new ConcurrentHashMap<>();

    private final AtomicInteger loginFailedLast10m = new AtomicInteger(0);
    private final AtomicInteger http401Last5m = new AtomicInteger(0);
    private final AtomicInteger frontendErrorsLast10m = new AtomicInteger(0);

    public MonitoringMetricsService(MeterRegistry meterRegistry) {
        this.loginSuccessCounter = Counter.builder("security_auth_login_success_total")
                .description("Total successful login attempts")
                .register(meterRegistry);
        this.loginFailedCounter = Counter.builder("security_auth_login_failed_total")
                .description("Total failed login attempts")
                .register(meterRegistry);
        this.loginLockedCounter = Counter.builder("security_auth_login_locked_total")
                .description("Total logins denied due to temporary lockout")
                .register(meterRegistry);
        this.http401Counter = Counter.builder("security_http_401_total")
                .description("Total HTTP 401 responses")
                .register(meterRegistry);
        this.frontendJsErrorCounter = Counter.builder("security_frontend_js_errors_total")
                .description("Total JavaScript runtime errors reported by the frontend")
                .register(meterRegistry);
        this.frontendUnhandledRejectionCounter = Counter.builder("security_frontend_unhandled_rejections_total")
                .description("Total unhandled promise rejections reported by the frontend")
                .register(meterRegistry);
        this.frontendCspViolationCounter = Counter.builder("security_frontend_csp_violations_total")
                .description("Total CSP violation events reported by the frontend")
                .register(meterRegistry);
        this.frontendScriptInjectionCounter = Counter.builder("security_frontend_script_injection_suspected_total")
            .description("Total suspected script injection events reported by the frontend")
            .register(meterRegistry);
        this.frontendApiFailureSpikeCounter = Counter.builder("security_frontend_api_failure_spikes_total")
            .description("Total frontend API failure spikes reported by the frontend")
            .register(meterRegistry);
        this.anomalyAlertCounter = Counter.builder("security_anomaly_alerts_total")
            .description("Total anomaly alerts triggered by the backend detector")
            .register(meterRegistry);

        Gauge.builder("security_auth_login_failed_last_10m", loginFailedLast10m, AtomicInteger::get)
            .description("Recent failed login attempts in the last 10 minutes")
            .register(meterRegistry);
        Gauge.builder("security_http_401_last_5m", http401Last5m, AtomicInteger::get)
            .description("Recent HTTP 401 responses in the last 5 minutes")
            .register(meterRegistry);
        Gauge.builder("security_frontend_errors_last_10m", frontendErrorsLast10m, AtomicInteger::get)
            .description("Recent frontend errors in the last 10 minutes")
            .register(meterRegistry);
    }

    public void incrementLoginSuccess() {
        loginSuccessCounter.increment();
        recordEvent("LOGIN_SUCCESS");
    }

    public void incrementLoginFailed() {
        loginFailedCounter.increment();
        recordEvent("LOGIN_FAILED");
    }

    public void incrementLoginLocked() {
        loginLockedCounter.increment();
        recordEvent("LOGIN_LOCKED");
    }

    public void incrementHttp401() {
        http401Counter.increment();
        recordEvent("HTTP_401");
    }

    public void incrementFrontendEvent(String eventType) {
        if (eventType == null) {
            frontendJsErrorCounter.increment();
            return;
        }
        switch (eventType.toUpperCase()) {
            case "UNHANDLED_REJECTION" -> frontendUnhandledRejectionCounter.increment();
            case "CSP_VIOLATION" -> frontendCspViolationCounter.increment();
            case "SCRIPT_INJECTION_SUSPECTED" -> frontendScriptInjectionCounter.increment();
            case "API_FAILURE_SPIKE" -> frontendApiFailureSpikeCounter.increment();
            default -> frontendJsErrorCounter.increment();
        }
        recordEvent("FRONTEND_" + eventType.toUpperCase());
    }

    public int getRecentCount(String eventKey, Duration window) {
        Deque<Instant> deque = rollingEventWindows.computeIfAbsent(eventKey, ignored -> new ConcurrentLinkedDeque<>());
        pruneOlderThan(deque, Instant.now().minus(window));
        return deque.size();
    }

    public void refreshDerivedGauges() {
        loginFailedLast10m.set(getRecentCount("LOGIN_FAILED", Duration.ofMinutes(10)));
        http401Last5m.set(getRecentCount("HTTP_401", Duration.ofMinutes(5)));

        int jsErrors = getRecentCount("FRONTEND_JS_ERROR", Duration.ofMinutes(10));
        int promiseErrors = getRecentCount("FRONTEND_UNHANDLED_REJECTION", Duration.ofMinutes(10));
        int cspErrors = getRecentCount("FRONTEND_CSP_VIOLATION", Duration.ofMinutes(10));
        int scriptEvents = getRecentCount("FRONTEND_SCRIPT_INJECTION_SUSPECTED", Duration.ofMinutes(10));
        int apiSpikes = getRecentCount("FRONTEND_API_FAILURE_SPIKE", Duration.ofMinutes(10));
        frontendErrorsLast10m.set(jsErrors + promiseErrors + cspErrors + scriptEvents + apiSpikes);
    }

    public void incrementAnomalyAlert() {
        anomalyAlertCounter.increment();
    }

    private void recordEvent(String eventKey) {
        Deque<Instant> deque = rollingEventWindows.computeIfAbsent(eventKey, ignored -> new ConcurrentLinkedDeque<>());
        deque.addLast(Instant.now());
        pruneOlderThan(deque, Instant.now().minus(Duration.ofMinutes(20)));
    }

    private void pruneOlderThan(Deque<Instant> deque, Instant oldestAllowed) {
        Instant candidate = deque.peekFirst();
        while (candidate != null && candidate.isBefore(oldestAllowed)) {
            deque.pollFirst();
            candidate = deque.peekFirst();
        }
    }
}
