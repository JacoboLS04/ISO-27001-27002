# AGENTS.md

## Purpose
- This project is a Spring Boot 3.2 REST API demo for ISO 27001/27002-aligned security controls (auth, RBAC, logging).
- Main domain is user management (`admin` + regular users), not generic student CRUD yet.

## Existing AI Guidance Sources
- Source scanned: `README.md` (no other agent-rule files found in the repository).

## Architecture Map (Read First)
- Entry point: `src/main/java/com/iso27001/studentmgmt/StudentManagementApplication.java`.
- Layering is strict and simple: `controller -> service -> repository -> entity`.
- Security path is separate but cross-cutting: `security/` + `config/SecurityConfig.java`.
- `AuthController` delegates login to `AuthService`; registration goes through `UserService`.
- `UserController` handles `/users` read/delete; access control is enforced both in HTTP config and method-level annotations.

## Critical Request Flows
- Register (`POST /auth/register`): `AuthController.register` -> `UserService.register` -> `UserRepository.save`.
- Login (`POST /auth/login`): `AuthController.login` -> `AuthService.login` -> `AuthenticationManager` -> `JwtUtil.generateToken`.
- Authenticated requests: `JwtAuthenticationFilter` parses `Authorization: Bearer <token>`, loads principal via `UserDetailsServiceImpl`, and sets `SecurityContext`.
- Delete user (`DELETE /users/{id}`): guarded in `SecurityConfig` (`HttpMethod.DELETE` requires `ROLE_ADMIN`) and `@PreAuthorize` in `UserController.deleteUser`.

## Project-Specific Conventions
- Roles are stored as enum names (`ROLE_ADMIN`, `ROLE_USER`) and passed as `SimpleGrantedAuthority` values unchanged.
- Invalid role input on registration does **not** fail; `UserService.parseRole` defaults to `ROLE_USER` and logs a warning.
- Password policy is enforced in DTO validation (`RegisterRequest`): min 8 chars + uppercase + digit.
- Validation errors are returned as field-to-message maps by `GlobalExceptionHandler.handleValidationErrors`.
- Audit-style security logs are explicit (`LOGIN_SUCCESS`, `LOGIN_FAILED`, `USER_REGISTERED`, `USER_DELETED`).

## Runtime and Data Behavior
- DB is in-memory H2 (`application.properties`), schema `create-drop`; data is reset on restart.
- Seed users are created in `DataInitializer`: `admin/Admin123` and `user1/User1234`.
- JWT uses HS256 via `app.jwt.secret` and `app.jwt.expiration-ms`.
- Log output writes to console and rolling files (`logs/application.log`, daily rotation, 30-day history) via `logback-spring.xml`.

## Developer Workflows
- Run app: `mvn spring-boot:run`
- Run tests: `mvn test`
- Package artifact: `mvn clean package`
- Integration tests use `MockMvc` in `src/test/java/com/iso27001/studentmgmt/StudentManagementApplicationTests.java` and rely on seeded users + token helper flow.

## Safe Change Guidance for Agents
- If changing authorization, update both `SecurityConfig.filterChain` and method annotations/tests to keep behavior consistent.
- If changing auth payloads/claims, update `JwtUtil`, controller DTO responses, and tests that parse `token`.
- Do not assume persistent data across runs/tests because H2 is ephemeral and tests use `@DirtiesContext`.
- Keep security-event logging semantics intact unless explicitly asked to change audit behavior.

