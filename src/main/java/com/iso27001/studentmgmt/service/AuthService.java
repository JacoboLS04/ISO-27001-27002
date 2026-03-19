package com.iso27001.studentmgmt.service;

import com.iso27001.studentmgmt.dto.AuthResponse;
import com.iso27001.studentmgmt.dto.LoginRequest;
import com.iso27001.studentmgmt.entity.User;
import com.iso27001.studentmgmt.repository.UserRepository;
import com.iso27001.studentmgmt.security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final SecurityAuditService securityAuditService;

    private final Map<String, Integer> failedAttempts = new ConcurrentHashMap<>();
    private final Map<String, Instant> lockoutUntil = new ConcurrentHashMap<>();
        private static final List<String> DISALLOWED_GENERIC_ACCOUNTS =
            List.of("admin", "root", "administrator");

    @Value("${app.auth.max-failed-attempts:5}")
    private int maxFailedAttempts;

    @Value("${app.auth.lockout-minutes:15}")
    private int lockoutMinutes;

    public AuthService(AuthenticationManager authenticationManager,
                       JwtUtil jwtUtil,
                       UserRepository userRepository,
                       SecurityAuditService securityAuditService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.securityAuditService = securityAuditService;
    }

    /**
     * Authenticate a user and return a JWT.
     * Successful and failed login attempts are logged for audit purposes
     * (ISO 27002 – logging and monitoring).
     */
    public AuthResponse login(LoginRequest request) {
        String username = normalizeUsername(request.getUsername());

        if (isDisallowedGenericAccount(username)) {
            logger.warn("GENERIC_ACCOUNT_BLOCKED username='{}'", username);
            securityAuditService.publish("GENERIC_ACCOUNT_BLOCKED", username, "FAILED", "Generic/shared account is blocked");
            throw new BadCredentialsException("Invalid username or password");
        }

        if (isLocked(username)) {
            logger.warn("ACCOUNT_LOCKED username='{}'", username);
            securityAuditService.publish("LOGIN", username, "FAILED", "Account temporarily locked");
            throw new LockedException("Account temporarily locked");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(), request.getPassword()));

            String authenticatedUsername = authentication.getName();
                User user = userRepository.findByUsername(authenticatedUsername)
                    .orElseThrow(() -> new BadCredentialsException("User not found"));

            clearFailedAttempts(username);

            String token = jwtUtil.generateToken(authenticatedUsername, user.getRole().name());
            logger.info("LOGIN_SUCCESS username='{}'", authenticatedUsername);
            securityAuditService.publish("LOGIN", authenticatedUsername, "SUCCESS", "Authentication successful");
            return new AuthResponse(token, authenticatedUsername, user.getRole().name());

        } catch (BadCredentialsException e) {
            int attempts = registerFailedAttempt(username);
            logger.warn("LOGIN_FAILED username='{}' reason='Bad credentials' attempts='{}'", username, attempts);
            securityAuditService.publish("LOGIN", username, "FAILED", "Invalid credentials, attempts=" + attempts);

            if (attempts >= maxFailedAttempts) {
                lockoutUntil.put(username, Instant.now().plus(lockoutMinutes, ChronoUnit.MINUTES));
                failedAttempts.remove(username);
                logger.warn("ACCOUNT_LOCKED username='{}' lockoutMinutes='{}'", username, lockoutMinutes);
                securityAuditService.publish("ACCOUNT_LOCKED", username, "FAILED", "Temporary lockout applied for " + lockoutMinutes + " minutes");
            }

            throw e;
        }
    }

    public void verifyCredentials(String username, String password) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
    }

    private String normalizeUsername(String username) {
        if (username == null) {
            return "";
        }
        return username.trim().toLowerCase(Locale.ROOT);
    }

    private boolean isLocked(String username) {
        Instant until = lockoutUntil.get(username);
        if (until == null) {
            return false;
        }
        if (until.isAfter(Instant.now())) {
            return true;
        }
        lockoutUntil.remove(username);
        return false;
    }

    private boolean isDisallowedGenericAccount(String username) {
        return DISALLOWED_GENERIC_ACCOUNTS.contains(username);
    }

    private int registerFailedAttempt(String username) {
        return failedAttempts.merge(username, 1, Integer::sum);
    }

    private void clearFailedAttempts(String username) {
        failedAttempts.remove(username);
        lockoutUntil.remove(username);
    }
}
