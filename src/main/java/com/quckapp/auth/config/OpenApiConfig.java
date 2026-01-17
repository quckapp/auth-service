package com.quckapp.auth.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.security.SecuritySchemes;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI/Swagger configuration for QuckApp Auth Service.
 *
 * Provides comprehensive API documentation with security schemes,
 * server configurations, and grouped API endpoints.
 */
@Configuration
@OpenAPIDefinition(
    info = @Info(
        title = "QuckApp Auth Service API",
        version = "1.0.0",
        description = """
            ## Authentication & Authorization Service

            The QuckApp Auth Service provides comprehensive authentication and authorization
            capabilities for the QuckApp ecosystem.

            ### Features
            - **Email/Password Authentication** - Traditional username/password login
            - **Phone OTP Authentication** - SMS-based one-time password login
            - **OAuth2 Social Login** - Google, Apple, Facebook, GitHub integration
            - **Two-Factor Authentication** - TOTP-based 2FA with backup codes
            - **JWT Token Management** - Access/refresh token lifecycle management
            - **Session Management** - Multi-device session tracking
            - **Rate Limiting** - Sliding window rate limiting per endpoint

            ### Authentication
            Most endpoints require a valid JWT Bearer token. Some endpoints also support
            API Key authentication for internal service-to-service communication.

            ### Rate Limits
            Rate limits vary by endpoint. Limits are based on IP address or authenticated user.
            When rate limited, responses include `X-RateLimit-*` headers.
            """,
        contact = @Contact(
            name = "QuckApp Team",
            email = "support@quckapp.com",
            url = "https://quckapp.com"
        ),
        license = @License(
            name = "MIT License",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    servers = {
        @Server(url = "/api/auth", description = "Auth Service Base Path"),
        @Server(url = "http://localhost:8081/api/auth", description = "Local Development"),
        @Server(url = "https://api.quckapp.com/auth", description = "Production")
    },
    tags = {
        @Tag(name = "Authentication", description = "User authentication endpoints including login, registration, and password management"),
        @Tag(name = "Token Management", description = "JWT token operations - refresh, validate, and revoke tokens"),
        @Tag(name = "Two-Factor Authentication", description = "2FA setup, verification, and backup code management"),
        @Tag(name = "Phone Authentication", description = "Phone-based OTP authentication for SMS login"),
        @Tag(name = "OAuth2", description = "Social login with Google, Apple, Facebook, and GitHub"),
        @Tag(name = "Sessions", description = "Active session management and device tracking"),
        @Tag(name = "User Profiles", description = "User profile CRUD operations and settings management"),
        @Tag(name = "Devices", description = "Device linking, FCM tokens, and push notification management"),
        @Tag(name = "Blocked Users", description = "User blocking and unblocking operations"),
        @Tag(name = "Admin", description = "Administrative operations - user banning, role management"),
        @Tag(name = "Migration", description = "Data migration endpoints for internal use only"),
        @Tag(name = "Internal", description = "Internal service-to-service endpoints")
    }
)
@SecuritySchemes({
    @SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT",
        description = """
            JWT Bearer token authentication.

            Obtain a token by calling `/v1/login` with valid credentials.
            Include the token in the Authorization header:
            `Authorization: Bearer <token>`

            Access tokens expire after 15 minutes. Use `/v1/token/refresh` to obtain a new access token.
            """
    ),
    @SecurityScheme(
        name = "apiKey",
        type = SecuritySchemeType.APIKEY,
        in = SecuritySchemeIn.HEADER,
        parameterName = "X-API-Key",
        description = """
            API Key authentication for internal services.

            Used for service-to-service communication.
            Include the key in the X-API-Key header:
            `X-API-Key: <your-api-key>`
            """
    )
})
public class OpenApiConfig {

    /**
     * Public API group - endpoints accessible without authentication
     */
    @Bean
    public GroupedOpenApi publicApi() {
        return GroupedOpenApi.builder()
            .group("1. Public")
            .displayName("Public API")
            .pathsToMatch(
                "/v1/register",
                "/v1/login",
                "/v1/login/2fa",
                "/v1/password/forgot",
                "/v1/password/reset",
                "/v1/token/refresh",
                "/v1/token/validate",
                "/v1/auth/phone/**",
                "/v1/oauth/**",
                "/v1/oauth2/**"
            )
            .build();
    }

    /**
     * Authenticated API group - requires JWT Bearer token
     */
    @Bean
    public GroupedOpenApi authenticatedApi() {
        return GroupedOpenApi.builder()
            .group("2. Authenticated")
            .displayName("Authenticated API")
            .pathsToMatch(
                "/v1/logout",
                "/v1/password/change",
                "/v1/token/revoke",
                "/v1/token/revoke-all",
                "/v1/2fa/**",
                "/v1/sessions/**",
                "/v1/users/me/**"
            )
            .build();
    }

    /**
     * User management API group
     */
    @Bean
    public GroupedOpenApi userManagementApi() {
        return GroupedOpenApi.builder()
            .group("3. User Management")
            .displayName("User Management API")
            .pathsToMatch(
                "/v1/users/**"
            )
            .pathsToExclude(
                "/v1/users/me/**",
                "/v1/users/admin/**",
                "/v1/users/internal/**"
            )
            .build();
    }

    /**
     * Admin API group - requires admin role
     */
    @Bean
    public GroupedOpenApi adminApi() {
        return GroupedOpenApi.builder()
            .group("4. Admin")
            .displayName("Admin API")
            .pathsToMatch(
                "/v1/users/admin/**"
            )
            .build();
    }

    /**
     * Internal API group - service-to-service communication
     */
    @Bean
    public GroupedOpenApi internalApi() {
        return GroupedOpenApi.builder()
            .group("5. Internal")
            .displayName("Internal API")
            .pathsToMatch(
                "/v1/users/internal/**",
                "/v1/migration/**"
            )
            .build();
    }

    /**
     * All endpoints in one view
     */
    @Bean
    public GroupedOpenApi allApi() {
        return GroupedOpenApi.builder()
            .group("0. All Endpoints")
            .displayName("All Endpoints")
            .pathsToMatch("/v1/**")
            .build();
    }

    /**
     * Custom OpenAPI configuration for additional response codes and headers
     */
    @Bean
    public OpenApiCustomizer globalResponseCustomizer() {
        return openApi -> {
            // Add global response headers documentation
            openApi.getPaths().values().forEach(pathItem ->
                pathItem.readOperations().forEach(operation -> {
                    // Add rate limit headers to response documentation
                    if (operation.getResponses() != null &&
                        operation.getResponses().get("200") != null) {
                        var successResponse = operation.getResponses().get("200");
                        if (successResponse.getHeaders() == null) {
                            successResponse.setHeaders(new java.util.HashMap<>());
                        }
                        successResponse.getHeaders().put("X-RateLimit-Limit",
                            new io.swagger.v3.oas.models.headers.Header()
                                .description("Request limit per window")
                                .schema(new Schema<Integer>().type("integer")));
                        successResponse.getHeaders().put("X-RateLimit-Remaining",
                            new io.swagger.v3.oas.models.headers.Header()
                                .description("Remaining requests in current window")
                                .schema(new Schema<Integer>().type("integer")));
                        successResponse.getHeaders().put("X-RateLimit-Reset",
                            new io.swagger.v3.oas.models.headers.Header()
                                .description("Unix timestamp when the rate limit resets")
                                .schema(new Schema<Long>().type("integer").format("int64")));
                    }
                })
            );
        };
    }
}
