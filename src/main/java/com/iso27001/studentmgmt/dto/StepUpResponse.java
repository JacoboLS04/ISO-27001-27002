package com.iso27001.studentmgmt.dto;

public class StepUpResponse {

    private String token;
    private String expiresAt;

    public StepUpResponse(String token, String expiresAt) {
        this.token = token;
        this.expiresAt = expiresAt;
    }

    public String getToken() {
        return token;
    }

    public String getExpiresAt() {
        return expiresAt;
    }
}
