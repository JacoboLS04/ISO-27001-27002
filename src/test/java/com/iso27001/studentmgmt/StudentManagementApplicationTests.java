package com.iso27001.studentmgmt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iso27001.studentmgmt.dto.LoginRequest;
import com.iso27001.studentmgmt.dto.RegisterRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class StudentManagementApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    // ── Registration tests ────────────────────────────────────────────────────

    @Test
    void register_validUser_returns201() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setUsername("testuser");
        req.setPassword("Secret1234");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    void register_weakPassword_tooShort_returns400() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setUsername("weakuser");
        req.setPassword("Abc1");   // too short

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_weakPassword_noUppercase_returns400() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setUsername("weakuser2");
        req.setPassword("alllower1234");   // no uppercase

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_weakPassword_noNumber_returns400() throws Exception {
        RegisterRequest req = new RegisterRequest();
        req.setUsername("weakuser3");
        req.setPassword("NoNumberHere");   // no digit

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    // ── Login tests ───────────────────────────────────────────────────────────

    @Test
    void login_validCredentials_returnsToken() throws Exception {
        LoginRequest req = new LoginRequest();
        req.setUsername("admin");
        req.setPassword("Admin123");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.username").value("admin"));
    }

    @Test
    void login_badCredentials_returns401() throws Exception {
        LoginRequest req = new LoginRequest();
        req.setUsername("admin");
        req.setPassword("wrongpassword");

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    // ── RBAC / Users endpoint tests ───────────────────────────────────────────

    @Test
    void getUsers_withoutToken_returns401or403() throws Exception {
        mockMvc.perform(get("/users"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    void getUsers_withUserToken_returns200() throws Exception {
        String token = obtainToken("user1", "User1234");

        mockMvc.perform(get("/users")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void deleteUser_withUserRole_returns403() throws Exception {
        String token = obtainToken("user1", "User1234");

        mockMvc.perform(delete("/users/1")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void deleteUser_withAdminRole_returns200orNotFound() throws Exception {
        String token = obtainToken("admin", "Admin123");

        // Seed creates user with id 2 (user1)
        mockMvc.perform(delete("/users/2")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().is2xxSuccessful());
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private String obtainToken(String username, String password) throws Exception {
        LoginRequest req = new LoginRequest();
        req.setUsername(username);
        req.setPassword(password);

        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andReturn();

        String body = result.getResponse().getContentAsString();
        return objectMapper.readTree(body).get("token").asText();
    }
}
