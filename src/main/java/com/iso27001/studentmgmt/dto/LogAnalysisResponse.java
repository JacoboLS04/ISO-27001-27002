package com.iso27001.studentmgmt.dto;

import java.util.List;

public class LogAnalysisResponse {

    private LogAnalysisSummaryResponse summary;
    private List<LogEventResponse> events;

    public LogAnalysisSummaryResponse getSummary() {
        return summary;
    }

    public void setSummary(LogAnalysisSummaryResponse summary) {
        this.summary = summary;
    }

    public List<LogEventResponse> getEvents() {
        return events;
    }

    public void setEvents(List<LogEventResponse> events) {
        this.events = events;
    }
}
