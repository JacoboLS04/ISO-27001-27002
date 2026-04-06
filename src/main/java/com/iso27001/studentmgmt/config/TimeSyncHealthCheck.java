package com.iso27001.studentmgmt.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Locale;

@Component
public class TimeSyncHealthCheck implements ApplicationRunner {

    private static final Logger logger = LoggerFactory.getLogger(TimeSyncHealthCheck.class);

    @Value("${app.time-sync.check-enabled:true}")
    private boolean enabled;

    @Override
    public void run(ApplicationArguments args) {
        if (!enabled) {
            return;
        }

        String os = System.getProperty("os.name", "unknown").toLowerCase(Locale.ROOT);
        String now = Instant.now().toString();

        try {
            if (os.contains("win")) {
                String status = runCommand("w32tm", "/query", "/status");
                if (status.toLowerCase(Locale.ROOT).contains("local cmos clock")) {
                    logger.warn("TIME_SYNC_STATUS ntp='not-synchronized' source='local-cmos-clock' serverTime='{}'", now);
                } else {
                    logger.info("TIME_SYNC_STATUS ntp='synchronized' serverTime='{}'", now);
                }
                return;
            }

            String ntpSync = runCommand("timedatectl", "show", "-p", "NTPSynchronized", "--value").trim();
            if ("yes".equalsIgnoreCase(ntpSync) || "true".equalsIgnoreCase(ntpSync)) {
                logger.info("TIME_SYNC_STATUS ntp='synchronized' serverTime='{}'", now);
            } else {
                logger.warn("TIME_SYNC_STATUS ntp='not-synchronized' serverTime='{}'", now);
            }

        } catch (Exception e) {
            logger.warn("TIME_SYNC_STATUS ntp='unknown' reason='{}' serverTime='{}'", e.getMessage(), now);
        }
    }

    private String runCommand(String... command) throws Exception {
        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append('\n');
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IllegalStateException("command failed with code " + exitCode);
        }

        return output.toString();
    }
}
