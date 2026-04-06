package com.iso27001.studentmgmt.security;

import com.iso27001.studentmgmt.service.MonitoringMetricsService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class MonitoringAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final MonitoringMetricsService monitoringMetricsService;

    public MonitoringAuthenticationEntryPoint(MonitoringMetricsService monitoringMetricsService) {
        this.monitoringMetricsService = monitoringMetricsService;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        monitoringMetricsService.incrementHttp401();
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"Unauthorized\"}");
    }
}
