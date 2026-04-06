package com.iso27001.studentmgmt.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Service
public class RecaptchaVerificationService {

    private static final Logger logger = LoggerFactory.getLogger(RecaptchaVerificationService.class);

    private final RestTemplate restTemplate;
    private final boolean enabled;
    private final String verifyUrl;
    private final String secret;

    public RecaptchaVerificationService(
            @Value("${app.recaptcha.enabled:true}") boolean enabled,
            @Value("${app.recaptcha.verify-url:https://www.google.com/recaptcha/api/siteverify}") String verifyUrl,
            @Value("${app.recaptcha.secret:}") String secret
    ) {
        this.enabled = enabled;
        this.verifyUrl = verifyUrl;
        this.secret = secret;
        this.restTemplate = new RestTemplate();
    }

    public boolean verify(String captchaToken, String remoteIp) {
        if (!enabled) {
            return true;
        }

        if (captchaToken == null || captchaToken.isBlank()) {
            logger.warn("RECAPTCHA_FAILED reason='missing token'");
            return false;
        }

        if (secret == null || secret.isBlank()) {
            logger.error("RECAPTCHA_MISCONFIGURED reason='missing secret'");
            return false;
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("secret", secret);
            body.add("response", captchaToken);
            if (remoteIp != null && !remoteIp.isBlank()) {
                body.add("remoteip", remoteIp);
            }

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            ResponseEntity<RecaptchaResponse> response =
                    restTemplate.postForEntity(verifyUrl, request, RecaptchaResponse.class);

            RecaptchaResponse payload = response.getBody();
            boolean ok = payload != null && Boolean.TRUE.equals(payload.getSuccess());

            if (!ok) {
                logger.warn("RECAPTCHA_FAILED errorCodes='{}'", payload != null ? payload.getErrorCodes() : List.of("unknown"));
            }

            return ok;
        } catch (RestClientException ex) {
            logger.error("RECAPTCHA_VERIFY_ERROR message='{}'", ex.getMessage());
            return false;
        }
    }

    public static class RecaptchaResponse {
        private Boolean success;

        @JsonProperty("error-codes")
        private List<String> errorCodes;

        public Boolean getSuccess() {
            return success;
        }

        public void setSuccess(Boolean success) {
            this.success = success;
        }

        public List<String> getErrorCodes() {
            return errorCodes;
        }

        public void setErrorCodes(List<String> errorCodes) {
            this.errorCodes = errorCodes;
        }
    }
}
