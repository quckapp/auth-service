# QuckApp Auth Service

Authentication and authorization microservice for QuckApp built with Spring Boot 3.2.

## Features

- Email/Password authentication
- Phone-based OTP authentication
- OAuth2 social login (Google, Apple, Facebook, GitHub)
- Two-Factor Authentication (2FA/TOTP)
- JWT token management with refresh tokens
- Session management
- User profile management
- Device linking and FCM token management
- User blocking functionality
- Role-based access control (RBAC)
- Data migration support

## Tech Stack

- **Framework:** Spring Boot 3.2.0
- **Language:** Java 21
- **Database:** MySQL 8.0
- **Cache:** Redis 7
- **Message Queue:** Apache Kafka
- **Security:** Spring Security, JWT (jjwt 0.12.3)
- **2FA:** TOTP (dev.samstevens.totp)
- **API Docs:** SpringDoc OpenAPI 2.3.0

## Prerequisites

- Java 21+
- Docker & Docker Compose
- MySQL 8.0
- Redis 7
- Kafka (optional for events)

## Quick Start

### Using Docker Compose

```bash
# Start all dependencies (MySQL, Redis, Kafka, Zookeeper)
docker-compose up -d

# The service will be available at http://localhost:8081/api/v1/auth
```

### Local Development

```bash
# Set environment variables
export DB_HOST=localhost
export DB_PORT=3306
export DB_NAME=quckapp_auth
export DB_USERNAME=root
export DB_PASSWORD=your_password
export REDIS_HOST=localhost
export REDIS_PORT=6379
export JWT_SECRET=your-256-bit-secret-key-change-in-production

# Build and run
./mvnw spring-boot:run
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8081` |
| `DB_HOST` | MySQL host | `localhost` |
| `DB_PORT` | MySQL port | `3306` |
| `DB_NAME` | Database name | `quckapp_auth` |
| `DB_USERNAME` | Database username | `root` |
| `DB_PASSWORD` | Database password | - |
| `REDIS_HOST` | Redis host | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `REDIS_PASSWORD` | Redis password | - |
| `KAFKA_BROKERS` | Kafka bootstrap servers | `localhost:9092` |
| `JWT_SECRET` | JWT signing secret (min 32 chars) | - |
| `ENCRYPTION_KEY` | Data encryption key (32 chars) | - |

### OAuth2 Providers

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `APPLE_CLIENT_ID` | Apple OAuth client ID |
| `APPLE_CLIENT_SECRET` | Apple OAuth client secret |
| `FACEBOOK_CLIENT_ID` | Facebook OAuth client ID |
| `FACEBOOK_CLIENT_SECRET` | Facebook OAuth client secret |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret |

## API Documentation

**Base URL:** `http://localhost:8081/api/v1/auth`

**Swagger UI:** http://localhost:8081/api/v1/auth/swagger-ui.html

**OpenAPI Spec:** http://localhost:8081/api/v1/auth/api-docs

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/register` | Register new user |
| `POST` | `/v1/login` | Login with email/password |
| `POST` | `/v1/login/2fa` | Complete login with 2FA code |
| `POST` | `/v1/logout` | Logout and revoke tokens |
| `POST` | `/v1/password/forgot` | Request password reset |
| `POST` | `/v1/password/reset` | Reset password with token |
| `POST` | `/v1/password/change` | Change password (authenticated) |

### Token Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/token/refresh` | Refresh access token |
| `POST` | `/v1/token/validate` | Validate JWT token |
| `POST` | `/v1/token/revoke` | Revoke a specific token |
| `POST` | `/v1/token/revoke-all` | Revoke all tokens for user |

### Two-Factor Authentication (2FA)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/2fa/setup` | Setup 2FA - get QR code |
| `POST` | `/v1/2fa/enable` | Enable 2FA after verification |
| `POST` | `/v1/2fa/disable` | Disable 2FA |
| `POST` | `/v1/2fa/backup-codes` | Generate new backup codes |

### Phone Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/auth/phone/request-otp` | Request OTP via SMS |
| `POST` | `/v1/auth/phone/verify-otp` | Verify OTP code |
| `POST` | `/v1/auth/phone/resend-otp` | Resend OTP |
| `POST` | `/v1/auth/phone/login` | Login/register with OTP |

### OAuth2

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/v1/oauth2/providers` | Get available OAuth2 providers |
| `GET` | `/v1/oauth2/authorize/{provider}` | Get authorization URL |
| `GET` | `/v1/oauth2/linked` | Get linked OAuth2 providers |
| `POST` | `/v1/oauth/{provider}` | Login/register with OAuth |
| `POST` | `/v1/oauth/{provider}/link` | Link OAuth to account |
| `DELETE` | `/v1/oauth/{provider}/unlink` | Unlink OAuth provider |

### Sessions

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/v1/sessions` | Get active sessions |
| `DELETE` | `/v1/sessions` | Terminate all other sessions |
| `DELETE` | `/v1/sessions/{sessionId}` | Terminate specific session |

### User Profiles

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/v1/users/me` | Get current user's profile |
| `PUT` | `/v1/users/me` | Update current user's profile |
| `PUT` | `/v1/users/me/status` | Update user status |
| `GET` | `/v1/users/me/settings` | Get user settings |
| `PUT` | `/v1/users/me/settings` | Update user settings |
| `GET` | `/v1/users/{userId}` | Get profile by user ID |
| `GET` | `/v1/users/by-username/{username}` | Get profile by username |
| `GET` | `/v1/users/by-phone/{phoneNumber}` | Get profile by phone |
| `GET` | `/v1/users/by-external-id/{externalId}` | Get profile by external ID |
| `GET` | `/v1/users/batch` | Get multiple profiles by IDs |
| `GET` | `/v1/users/batch/external` | Get profiles by external IDs |
| `GET` | `/v1/users/search` | Search users |

### Devices

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/v1/users/me/devices` | Get linked devices |
| `POST` | `/v1/users/me/devices` | Link a device |
| `DELETE` | `/v1/users/me/devices/{deviceId}` | Unlink a device |
| `PUT` | `/v1/users/me/devices/{deviceId}/fcm-token` | Update FCM token |
| `PUT` | `/v1/users/me/devices/{deviceId}/activity` | Update device activity |

### Blocked Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/v1/users/me/blocked-users` | Get blocked users |
| `POST` | `/v1/users/me/blocked-users` | Block a user |
| `DELETE` | `/v1/users/me/blocked-users/{blockedUserId}` | Unblock a user |

### Admin Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/users/admin/ban` | Ban a user |
| `POST` | `/v1/users/admin/unban/{userId}` | Unban a user |
| `POST` | `/v1/users/admin/role` | Update user role |
| `POST` | `/v1/users/admin/permissions` | Update user permissions |
| `GET` | `/v1/users/admin/statistics` | Get user statistics |

### Internal Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/v1/users/internal/fcm-tokens/{userId}` | Get FCM tokens (internal) |
| `POST` | `/v1/users/internal/fcm-tokens/batch` | Get FCM tokens batch (internal) |
| `GET` | `/v1/users/internal/check-blocked` | Check if users blocked (internal) |

### Migration Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/migration/users/batch` | Batch import users |
| `POST` | `/v1/migration/settings/batch` | Batch import settings |
| `POST` | `/v1/migration/validate` | Validate migration |
| `GET` | `/v1/migration/status` | Get migration status |

## Request/Response Examples

### Register

```bash
curl -X POST http://localhost:8081/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

### Login

```bash
curl -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "deviceId": "device-123",
    "deviceName": "My Phone"
  }'
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "refreshToken": "dGhpcyBpcyBhIHJlZnJlc2g...",
  "expiresIn": 3600,
  "tokenType": "Bearer",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "twoFactorEnabled": false
  }
}
```

### Refresh Token

```bash
curl -X POST http://localhost:8081/api/v1/auth/token/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "your-refresh-token"
  }'
```

### Phone OTP Login

```bash
# Request OTP
curl -X POST http://localhost:8081/api/v1/auth/phone/request-otp \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "+1234567890"
  }'

# Verify and Login
curl -X POST http://localhost:8081/api/v1/auth/phone/login \
  -H "Content-Type: application/json" \
  -d '{
    "phoneNumber": "+1234567890",
    "code": "123456"
  }'
```

## Health Check

```bash
curl http://localhost:8081/api/v1/auth/actuator/health
```

**Response:**
```json
{
  "status": "UP"
}
```

## Metrics

Prometheus metrics available at: `http://localhost:8081/api/v1/auth/actuator/prometheus`

## Testing

```bash
# Run all tests
./mvnw test

# Run with coverage
./mvnw test jacoco:report
```

## Docker

### Build Image

```bash
docker build -t quckapp/auth-service:latest .
```

### Run Container

```bash
docker run -p 8081:8081 \
  -e DB_HOST=host.docker.internal \
  -e REDIS_HOST=host.docker.internal \
  -e JWT_SECRET=your-secret-key \
  quckapp/auth-service:latest
```

## Port Mapping (Development)

| Service | Port |
|---------|------|
| Auth Service | 8081 |
| MySQL | 3308 |
| Redis | 6379 |
| Kafka | 9092, 29092 |
| Zookeeper | 2181 |

## License

MIT License - see [LICENSE](LICENSE) for details.
