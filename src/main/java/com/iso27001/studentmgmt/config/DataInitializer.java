package com.iso27001.studentmgmt.config;

import com.iso27001.studentmgmt.entity.Role;
import com.iso27001.studentmgmt.entity.User;
import com.iso27001.studentmgmt.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataInitializer {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Bean
    public CommandLineRunner seedData(UserRepository userRepository,
                                      PasswordEncoder passwordEncoder) {
        return args -> {
            if (!userRepository.existsByUsername("admin.iso")) {
                userRepository.save(new User("admin.iso", passwordEncoder.encode("Admin123"), Role.ROLE_ADMIN));
                logger.info("Seeded default admin user (username=admin.iso)");
            }
            if (!userRepository.existsByUsername("user1")) {
                userRepository.save(new User("user1", passwordEncoder.encode("User1234"), Role.ROLE_USER));
                logger.info("Seeded default regular user (username=user1)");
            }
        };
    }
}
