package com.iso27001.studentmgmt.controller;

import com.iso27001.studentmgmt.dto.AuthResponse;
import com.iso27001.studentmgmt.dto.LoginRequest;
import com.iso27001.studentmgmt.dto.RegisterRequest;
import com.iso27001.studentmgmt.dto.StepUpRequest;
import com.iso27001.studentmgmt.dto.StepUpResponse;
import com.iso27001.studentmgmt.dto.UserResponse;
import com.iso27001.studentmgmt.service.AuthService;
import com.iso27001.studentmgmt.service.RecaptchaVerificationService;
import com.iso27001.studentmgmt.service.SecurityAuditService;
import com.iso27001.studentmgmt.service.StepUpAuthService;
import com.iso27001.studentmgmt.service.UserService;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final UserService userService;
    private final RecaptchaVerificationService recaptchaVerificationService;
    private final StepUpAuthService stepUpAuthService;
    private final SecurityAuditService securityAuditService;

    public AuthController(AuthService authService,
                          UserService userService,
                          RecaptchaVerificationService recaptchaVerificationService,
                          StepUpAuthService stepUpAuthService,
                          SecurityAuditService securityAuditService) {
        this.authService = authService;
        this.userService = userService;
        this.recaptchaVerificationService = recaptchaVerificationService;
        this.stepUpAuthService = stepUpAuthService;
        this.securityAuditService = securityAuditService;
    }

    /**
     * POST /auth/register
     * Register a new user. Validates password policy via Bean Validation annotations on RegisterRequest.
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request,
                                      HttpServletRequest servletRequest) {
        try {
            boolean captchaOk = recaptchaVerificationService.verify(
                    request.getCaptchaToken(),
                    servletRequest.getRemoteAddr());

            if (!captchaOk) {
                logger.warn("RECAPTCHA_FAILED username='{}' endpoint='/auth/register'", request.getUsername());
                securityAuditService.publish("RECAPTCHA", request.getUsername(), "FAILED", "Register request blocked by reCAPTCHA");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "reCAPTCHA validation failed"));
            }

            UserResponse response = userService.register(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * POST /auth/login
     * Authenticate with username and password; returns a JWT on success.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request,
                                   HttpServletRequest servletRequest) {
        try {
            boolean captchaOk = recaptchaVerificationService.verify(
                    request.getCaptchaToken(),
                    servletRequest.getRemoteAddr());

            if (!captchaOk) {
                logger.warn("RECAPTCHA_FAILED username='{}' endpoint='/auth/login'", request.getUsername());
                securityAuditService.publish("RECAPTCHA", request.getUsername(), "FAILED", "Login request blocked by reCAPTCHA");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("error", "reCAPTCHA validation failed"));
            }

            AuthResponse response = authService.login(request);
            return ResponseEntity.ok(response);
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid username or password"));
        } catch (LockedException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid username or password"));
        }
    }

    /**
     * POST /auth/step-up
     * Re-authentication endpoint required before privileged operations.
     */
    @PostMapping("/step-up")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<?> stepUp(@Valid @RequestBody StepUpRequest request,
                                    Principal principal) {
        try {
            authService.verifyCredentials(principal.getName(), request.getPassword());
            StepUpAuthService.StepUpToken token = stepUpAuthService.issueToken(principal.getName());
            securityAuditService.publish("STEP_UP", principal.getName(), "SUCCESS", "Step-up challenge successful");

            return ResponseEntity.ok(new StepUpResponse(token.getToken(), token.getExpiresAtIso()));
        } catch (BadCredentialsException e) {
            securityAuditService.publish("STEP_UP", principal.getName(), "FAILED", "Step-up credentials invalid");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Step-up authentication failed"));
        }
    }
}
