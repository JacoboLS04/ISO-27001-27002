package com.iso27001.studentmgmt.controller;

import com.iso27001.studentmgmt.dto.LogAnalysisResponse;
import com.iso27001.studentmgmt.service.LogAnalysisService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/logs")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AdminLogController {

    private final LogAnalysisService logAnalysisService;

    public AdminLogController(LogAnalysisService logAnalysisService) {
        this.logAnalysisService = logAnalysisService;
    }

    @GetMapping("/analysis")
    public LogAnalysisResponse getLogAnalysis(@RequestParam(defaultValue = "150") int limit) {
        return logAnalysisService.analyzeRecentEvents(limit);
    }
}
