package com.iso27001.studentmgmt.dto;

import java.util.Map;

public class LogAnalysisSummaryResponse {

    private int totalEvents;
    private int successfulEvents;
    private int failedEvents;
    private double riskScore;
    private String riskLevel;
    private Map<String, Integer> eventsByType;
    private Map<String, Integer> eventsByUser;

    public int getTotalEvents() {
        return totalEvents;
    }

    public void setTotalEvents(int totalEvents) {
        this.totalEvents = totalEvents;
    }

    public int getSuccessfulEvents() {
        return successfulEvents;
    }

    public void setSuccessfulEvents(int successfulEvents) {
        this.successfulEvents = successfulEvents;
    }

    public int getFailedEvents() {
        return failedEvents;
    }

    public void setFailedEvents(int failedEvents) {
        this.failedEvents = failedEvents;
    }

    public double getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(double riskScore) {
        this.riskScore = riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public Map<String, Integer> getEventsByType() {
        return eventsByType;
    }

    public void setEventsByType(Map<String, Integer> eventsByType) {
        this.eventsByType = eventsByType;
    }

    public Map<String, Integer> getEventsByUser() {
        return eventsByUser;
    }

    public void setEventsByUser(Map<String, Integer> eventsByUser) {
        this.eventsByUser = eventsByUser;
    }
}
