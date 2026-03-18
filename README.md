# ISO-27001-27002 – Student Management System

A minimal Spring Boot REST API that demonstrates security controls aligned with **ISO/IEC 27001 and 27002**.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Java 17 |
| Framework | Spring Boot 3.2 |
| Security | Spring Security + JWT (JJWT 0.11) |
| Persistence | Spring Data JPA / Hibernate |
| Database | H2 (in-memory) |
| Build | Maven |
| Logging | Logback (console + rolling file) |

---

## Security Controls Implemented

| Control | ISO Reference | Implementation |
|---|---|---|
| Authentication | 27001 A.9 | Spring Security + BCrypt + JWT |
| Password Policy | 27002 9.4 | Bean Validation: min 8 chars, uppercase, digit |
| Logging & Monitoring | 27001 A.12.4 | Logback – login success/failure, registration |
| Role-Based Access Control | 27002 9.2 | `ROLE_ADMIN` / `ROLE_USER` via Spring Security |

---

## Project Structure

```
src/
└── main/
    ├── java/com/iso27001/studentmgmt/
    │   ├── StudentManagementApplication.java
    │   ├── config/
    │   │   ├── DataInitializer.java       ← seed data
    │   │   ├── GlobalExceptionHandler.java
    │   │   └── SecurityConfig.java
    │   ├── controller/
    │   │   ├── AuthController.java        ← /auth/register, /auth/login
    │   │   └── UserController.java        ← GET /users, DELETE /users/{id}
    │   ├── dto/
    │   │   ├── AuthResponse.java
    │   │   ├── LoginRequest.java
    │   │   ├── RegisterRequest.java
    │   │   └── UserResponse.java
    │   ├── entity/
    │   │   ├── Role.java                  ← ROLE_ADMIN, ROLE_USER
    │   │   └── User.java
    │   ├── repository/
    │   │   └── UserRepository.java
    │   ├── security/
    │   │   ├── JwtAuthenticationFilter.java
    │   │   ├── JwtUtil.java
    │   │   └── UserDetailsServiceImpl.java
    │   └── service/
    │       ├── AuthService.java
    │       └── UserService.java
    └── resources/
        ├── application.properties
        └── logback-spring.xml
```

---

## Running Locally

### Prerequisites

- Java 17+
- Maven 3.8+

### Steps

```bash
# Clone / navigate to project root
cd ISO-27001-27002

# Build and run
mvn spring-boot:run
```

The API is available at **http://localhost:8080**.

H2 console: **http://localhost:8080/h2-console**
JDBC URL: `jdbc:h2:mem:studentdb`

---

## Seeded Users

| Username | Password  | Role       |
|----------|-----------|------------|
| admin    | Admin123  | ROLE_ADMIN |
| user1    | User1234  | ROLE_USER  |

---

## API Endpoints

### Register a new user

```bash
POST /auth/register
Content-Type: application/json

{
  "username": "alice",
  "password": "Alice2024",
  "role": "ROLE_USER"
}
```

Password rules: ≥ 8 characters, at least one uppercase letter, at least one digit.

### Login

```bash
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "Admin123"
}
```

Returns:
```json
{ "token": "<JWT>", "username": "admin", "role": "ROLE_ADMIN" }
```

### List users (any authenticated user)

```bash
GET /users
Authorization: Bearer <JWT>
```

### Delete user (ROLE_ADMIN only)

```bash
DELETE /users/{id}
Authorization: Bearer <JWT>
```

---

## Running Tests

```bash
mvn test
```