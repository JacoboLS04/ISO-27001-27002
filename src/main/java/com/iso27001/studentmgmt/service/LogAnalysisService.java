package com.iso27001.studentmgmt.service;

import com.iso27001.studentmgmt.dto.LogAnalysisResponse;
import com.iso27001.studentmgmt.dto.LogAnalysisSummaryResponse;
import com.iso27001.studentmgmt.dto.LogEventResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class LogAnalysisService {

    private static final Logger logger = LoggerFactory.getLogger(LogAnalysisService.class);

    private static final DateTimeFormatter LOG_DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final Pattern LOGIN_SUCCESS_PATTERN = Pattern.compile("LOGIN_SUCCESS username='([^']+)'", Pattern.CASE_INSENSITIVE);
    private static final Pattern LOGIN_FAILED_PATTERN = Pattern.compile("LOGIN_FAILED username='([^']+)'", Pattern.CASE_INSENSITIVE);
    private static final Pattern USER_REGISTERED_PATTERN = Pattern.compile("USER_REGISTERED username='([^']+)'", Pattern.CASE_INSENSITIVE);
    private static final Pattern USER_DELETED_PATTERN = Pattern.compile("USER_DELETED id='([^']+)'", Pattern.CASE_INSENSITIVE);
    private static final Pattern RECAPTCHA_FAILED_PATTERN = Pattern.compile("RECAPTCHA_FAILED username='([^']+)'", Pattern.CASE_INSENSITIVE);
    private static final Pattern STEP_UP_ISSUED_PATTERN = Pattern.compile("STEP_UP_ISSUED username='([^']+)'", Pattern.CASE_INSENSITIVE);
    private static final Pattern STEP_UP_CONSUMED_PATTERN = Pattern.compile("STEP_UP_CONSUMED username='([^']+)'", Pattern.CASE_INSENSITIVE);
    private static final Pattern STEP_UP_INVALID_PATTERN = Pattern.compile("STEP_UP_(INVALID|EXPIRED) username='([^']+)'", Pattern.CASE_INSENSITIVE);
    private static final Pattern AUDIT_EVENT_PATTERN = Pattern.compile("AUDIT_EVENT type='([^']+)' username='([^']+)' status='([^']+)'", Pattern.CASE_INSENSITIVE);

    @Value("${app.log.analysis.file-path:logs/application.log}")
    private String logFilePath;

    public LogAnalysisResponse analyzeRecentEvents(int limit) {
        List<LogEventResponse> events = readAuditEvents(limit);

        LogAnalysisSummaryResponse summary = new LogAnalysisSummaryResponse();
        summary.setTotalEvents(events.size());

        int successful = (int) events.stream()
                .filter(e -> "SUCCESS".equalsIgnoreCase(e.getStatus()))
                .count();
        int failed = (int) events.stream()
                .filter(e -> "FAILED".equalsIgnoreCase(e.getStatus()))
                .count();

        summary.setSuccessfulEvents(successful);
        summary.setFailedEvents(failed);

        double riskScore = events.isEmpty() ? 0.0 : ((double) failed / (double) events.size()) * 100.0;
        summary.setRiskScore(Math.round(riskScore * 100.0) / 100.0);
        summary.setRiskLevel(calculateRiskLevel(riskScore));

        Map<String, Integer> byType = events.stream()
                .collect(Collectors.toMap(
                        LogEventResponse::getEventType,
                        e -> 1,
                        Integer::sum,
                        HashMap::new
                ));

        Map<String, Integer> byUser = events.stream()
                .collect(Collectors.toMap(
                        e -> e.getUsername() == null ? "unknown" : e.getUsername(),
                        e -> 1,
                        Integer::sum,
                        HashMap::new
                ));

        summary.setEventsByType(byType);
        summary.setEventsByUser(byUser);

        LogAnalysisResponse response = new LogAnalysisResponse();
        response.setSummary(summary);
        response.setEvents(events);
        return response;
    }

    private List<LogEventResponse> readAuditEvents(int limit) {
        Path path = Paths.get(logFilePath);
        if (!Files.exists(path)) {
            logger.warn("Log file not found at path '{}'", logFilePath);
            return List.of();
        }

        try (Stream<String> lines = Files.lines(path)) {
            return lines
                    .map(this::parseLine)
                    .filter(e -> e != null)
                    .sorted(Comparator.comparing(this::parseTimestampSafe).reversed())
                    .limit(Math.max(1, limit))
                    .collect(Collectors.toList());
        } catch (IOException e) {
            logger.error("Unable to read log file '{}'", logFilePath, e);
            return List.of();
        }
    }

    private LogEventResponse parseLine(String line) {
        if (line == null || line.isBlank()) {
            return null;
        }

        // Expected pattern from logback:
        // 2026-03-18 20:10:44 [thread] INFO logger - message
        if (line.length() < 19) {
            return null;
        }

        String timestamp = line.substring(0, 19);

        int levelIndexStart = line.indexOf(']');
        if (levelIndexStart < 0 || levelIndexStart + 1 >= line.length()) {
            return null;
        }

        String afterThread = line.substring(levelIndexStart + 1).trim();
        if (afterThread.isBlank()) {
            return null;
        }

        String level = afterThread.split("\\s+")[0].toUpperCase(Locale.ROOT);

        int dashIndex = line.indexOf(" - ");
        if (dashIndex < 0 || dashIndex + 3 >= line.length()) {
            return null;
        }

        String message = line.substring(dashIndex + 3).trim();
        ParsedEvent parsed = classifyMessage(message);
        if (parsed == null) {
            return null;
        }

        return new LogEventResponse(
                timestamp,
                level,
                parsed.eventType,
                parsed.username,
                parsed.status,
                message
        );
    }

    private ParsedEvent classifyMessage(String message) {
        Matcher m;

        m = LOGIN_SUCCESS_PATTERN.matcher(message);
        if (m.find()) {
            return new ParsedEvent("LOGIN", m.group(1), "SUCCESS");
        }

        m = LOGIN_FAILED_PATTERN.matcher(message);
        if (m.find()) {
            return new ParsedEvent("LOGIN", m.group(1), "FAILED");
        }

        m = RECAPTCHA_FAILED_PATTERN.matcher(message);
        if (m.find()) {
            return new ParsedEvent("RECAPTCHA", m.group(1), "FAILED");
        }

        m = USER_REGISTERED_PATTERN.matcher(message);
        if (m.find()) {
            return new ParsedEvent("USER_REGISTERED", m.group(1), "SUCCESS");
        }

        m = USER_DELETED_PATTERN.matcher(message);
        if (m.find()) {
            return new ParsedEvent("USER_DELETED", "admin", "SUCCESS");
        }

        m = STEP_UP_ISSUED_PATTERN.matcher(message);
        if (m.find()) {
            return new ParsedEvent("STEP_UP", m.group(1), "SUCCESS");
        }

        m = STEP_UP_CONSUMED_PATTERN.matcher(message);
        if (m.find()) {
            return new ParsedEvent("STEP_UP", m.group(1), "SUCCESS");
        }

        m = STEP_UP_INVALID_PATTERN.matcher(message);
        if (m.find()) {
            return new ParsedEvent("STEP_UP", m.group(2), "FAILED");
        }

        m = AUDIT_EVENT_PATTERN.matcher(message);
        if (m.find()) {
            return new ParsedEvent(m.group(1).toUpperCase(Locale.ROOT), m.group(2), m.group(3).toUpperCase(Locale.ROOT));
        }

        return null;
    }

    private LocalDateTime parseTimestampSafe(LogEventResponse event) {
        try {
            return LocalDateTime.parse(event.getTimestamp(), LOG_DATE_FORMAT);
        } catch (Exception ignored) {
            return LocalDateTime.MIN;
        }
    }

    private String calculateRiskLevel(double riskScore) {
        if (riskScore < 15) {
            return "LOW";
        }
        if (riskScore < 35) {
            return "MEDIUM";
        }
        return "HIGH";
    }

    private static class ParsedEvent {
        private final String eventType;
        private final String username;
        private final String status;

        private ParsedEvent(String eventType, String username, String status) {
            this.eventType = eventType;
            this.username = username;
            this.status = status;
        }
    }
}
