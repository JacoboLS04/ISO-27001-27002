package com.iso27001.studentmgmt.controller;

import com.iso27001.studentmgmt.dto.UserResponse;
import com.iso27001.studentmgmt.service.StepUpAuthService;
import com.iso27001.studentmgmt.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;
    private final StepUpAuthService stepUpAuthService;

    public UserController(UserService userService, StepUpAuthService stepUpAuthService) {
        this.userService = userService;
        this.stepUpAuthService = stepUpAuthService;
    }

    /**
     * GET /users
     * Returns the list of all users. Requires authentication (any role).
     */
    @GetMapping
    public ResponseEntity<List<UserResponse>> listUsers() {
        return ResponseEntity.ok(userService.findAll());
    }

    /**
     * DELETE /users/{id}
     * Deletes a user by id. Restricted to ROLE_ADMIN (enforced in SecurityConfig).
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id,
                                        @RequestHeader("X-Step-Up-Token") String stepUpToken,
                                        Authentication authentication) {
        try {
            boolean stepUpValid = stepUpAuthService.consumeToken(authentication.getName(), stepUpToken);
            if (!stepUpValid) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("error", "Step-up authentication required"));
            }

            userService.deleteById(id);
            return ResponseEntity.ok(Map.of("message", "User deleted successfully"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
    }
}
