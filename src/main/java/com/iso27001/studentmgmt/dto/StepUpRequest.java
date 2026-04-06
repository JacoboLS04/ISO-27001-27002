package com.iso27001.studentmgmt.dto;

import jakarta.validation.constraints.NotBlank;

public class StepUpRequest {

    @NotBlank(message = "Password is required")
    private String password;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
