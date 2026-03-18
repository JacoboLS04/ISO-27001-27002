package com.iso27001.studentmgmt.service;

import com.iso27001.studentmgmt.dto.AuthResponse;
import com.iso27001.studentmgmt.dto.LoginRequest;
import com.iso27001.studentmgmt.entity.User;
import com.iso27001.studentmgmt.repository.UserRepository;
import com.iso27001.studentmgmt.security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    public AuthService(AuthenticationManager authenticationManager,
                       JwtUtil jwtUtil,
                       UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
    }

    /**
     * Authenticate a user and return a JWT.
     * Successful and failed login attempts are logged for audit purposes
     * (ISO 27002 – logging and monitoring).
     */
    public AuthResponse login(LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(), request.getPassword()));

            String username = authentication.getName();
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new BadCredentialsException("User not found"));

            String token = jwtUtil.generateToken(username, user.getRole().name());
            logger.info("LOGIN_SUCCESS username='{}'", username);
            return new AuthResponse(token, username, user.getRole().name());

        } catch (BadCredentialsException e) {
            logger.warn("LOGIN_FAILED username='{}' reason='Bad credentials'", request.getUsername());
            throw e;
        }
    }
}
