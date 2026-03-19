package com.iso27001.studentmgmt.service;

import com.iso27001.studentmgmt.dto.RegisterRequest;
import com.iso27001.studentmgmt.dto.UserResponse;
import com.iso27001.studentmgmt.entity.Role;
import com.iso27001.studentmgmt.entity.User;
import com.iso27001.studentmgmt.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
        private static final List<String> DISALLOWED_GENERIC_USERNAMES =
            List.of("admin", "root", "administrator");

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecurityAuditService securityAuditService;

    public UserService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       SecurityAuditService securityAuditService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.securityAuditService = securityAuditService;
    }

    /**
     * Register a new user. Password is stored encrypted with BCrypt.
     * Logs the registration event for audit purposes (ISO 27002 – logging and monitoring).
     */
    public UserResponse register(RegisterRequest request) {
        String normalizedUsername = request.getUsername() == null
                ? ""
                : request.getUsername().trim().toLowerCase();

        if (DISALLOWED_GENERIC_USERNAMES.contains(normalizedUsername)) {
            securityAuditService.publish("USER_REGISTERED", normalizedUsername, "FAILED", "Generic/shared username rejected");
            throw new IllegalArgumentException("Generic or shared usernames are not allowed");
        }

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username already exists: " + request.getUsername());
        }

        Role role = parseRole(request.getRole());
        User user = new User(
                request.getUsername(),
                passwordEncoder.encode(request.getPassword()),
                role
        );
        User saved = userRepository.save(user);

        logger.info("USER_REGISTERED username='{}' role='{}'", saved.getUsername(), saved.getRole());
        securityAuditService.publish("USER_REGISTERED", saved.getUsername(), "SUCCESS", "User account created with role=" + saved.getRole());
        return toResponse(saved);
    }

    /**
     * Return all users (no passwords exposed).
     */
    public List<UserResponse> findAll() {
        return userRepository.findAll()
                .stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    /**
     * Delete a user by id (admin-only, enforced at controller/security level).
     */
    public void deleteById(Long id) {
        if (!userRepository.existsById(id)) {
            throw new IllegalArgumentException("User not found with id: " + id);
        }
        userRepository.deleteById(id);
        logger.info("USER_DELETED id='{}'", id);
        securityAuditService.publish("USER_DELETED", "admin", "SUCCESS", "User deleted id=" + id);
    }

    private Role parseRole(String roleStr) {
        if (roleStr == null || roleStr.isBlank()) {
            return Role.ROLE_USER;
        }
        try {
            return Role.valueOf(roleStr.toUpperCase());
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid role '{}' provided during registration – defaulting to ROLE_USER", roleStr);
            return Role.ROLE_USER;
        }
    }

    private UserResponse toResponse(User user) {
        return new UserResponse(user.getId(), user.getUsername(), user.getRole().name());
    }
}
