package com.iso27001.studentmgmt.dto;

public class LogEventResponse {

    private String timestamp;
    private String level;
    private String eventType;
    private String username;
    private String status;
    private String details;

    public LogEventResponse() {
    }

    public LogEventResponse(String timestamp,
                            String level,
                            String eventType,
                            String username,
                            String status,
                            String details) {
        this.timestamp = timestamp;
        this.level = level;
        this.eventType = eventType;
        this.username = username;
        this.status = status;
        this.details = details;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getLevel() {
        return level;
    }

    public void setLevel(String level) {
        this.level = level;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }
}
