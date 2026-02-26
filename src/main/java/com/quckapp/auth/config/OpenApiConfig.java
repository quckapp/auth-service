package com.quckapp.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * OpenAPI/Swagger configuration for QuckApp Auth Service.
 *
 * Environment-aware API documentation with security schemes,
 * server configurations, and grouped API endpoints.
 */
@Configuration
public class OpenApiConfig {

    private final Environment environment;

    @Value("${server.port:8081}")
    private int serverPort;

    @Value("${server.servlet.context-path:/api/v1/auth}")
    private String contextPath;

    public OpenApiConfig(Environment environment) {
        this.environment = environment;
    }

    /**
     * Get current active environment name
     */
    private String getActiveEnvironment() {
        String[] profiles = environment.getActiveProfiles();
        if (profiles.length > 0) {
            return profiles[0].toUpperCase();
        }
        return "DEFAULT";
    }

    /**
     * Get environment display info for the API title
     */
    private EnvironmentInfo getEnvironmentInfo() {
        String profile = getActiveEnvironment().toLowerCase();
        return switch (profile) {
            case "local" -> new EnvironmentInfo("LOCAL", "Local Development", "http://localhost:" + serverPort + contextPath, "#4CAF50");
            case "dev" -> new EnvironmentInfo("DEV", "Development", "http://localhost:" + serverPort + contextPath, "#2196F3");
            case "qa" -> new EnvironmentInfo("QA", "Quality Assurance", "http://localhost:" + serverPort + contextPath, "#FF9800");
            case "uat1" -> new EnvironmentInfo("UAT1", "User Acceptance Testing 1", "http://localhost:" + serverPort + contextPath, "#9C27B0");
            case "uat2" -> new EnvironmentInfo("UAT2", "User Acceptance Testing 2", "http://localhost:" + serverPort + contextPath, "#9C27B0");
            case "uat3" -> new EnvironmentInfo("UAT3", "User Acceptance Testing 3", "http://localhost:" + serverPort + contextPath, "#9C27B0");
            case "staging" -> new EnvironmentInfo("STAGING", "Staging", "https://staging-api.quckapp.com/auth", "#FF5722");
            case "production" -> new EnvironmentInfo("PRODUCTION", "Production", "https://api.quckapp.com/auth", "#F44336");
            case "live" -> new EnvironmentInfo("LIVE", "Live/Hot-standby", "https://live-api.quckapp.com/auth", "#E91E63");
            default -> new EnvironmentInfo("DEFAULT", "Default", "http://localhost:" + serverPort + contextPath, "#607D8B");
        };
    }

    /**
     * Configure OpenAPI with environment-specific settings
     */
    @Bean
    public OpenAPI customOpenAPI() {
        EnvironmentInfo envInfo = getEnvironmentInfo();
        String envBadge = "[" + envInfo.name + "]";

        return new OpenAPI()
            .info(new Info()
                .title("QuckApp Auth Service API " + envBadge)
                .version("1.0.0")
                .description(buildDescription(envInfo))
                .contact(new Contact()
                    .name("QuckApp Team")
                    .email("support@quckapp.com")
                    .url("https://quckapp.com"))
                .license(new License()
                    .name("MIT License")
                    .url("https://opensource.org/licenses/MIT")))
            .servers(buildServers(envInfo))
            .tags(buildTags())
            .components(new Components()
                .addSecuritySchemes("bearerAuth",
                    new io.swagger.v3.oas.models.security.SecurityScheme()
                        .type(io.swagger.v3.oas.models.security.SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("""
                            JWT Bearer token authentication.

                            Obtain a token by calling `/v1/login` with valid credentials.
                            Include the token in the Authorization header:
                            `Authorization: Bearer <token>`

                            Access tokens expire after 15 minutes. Use `/v1/token/refresh` to obtain a new access token.
                            """))
                .addSecuritySchemes("apiKey",
                    new io.swagger.v3.oas.models.security.SecurityScheme()
                        .type(io.swagger.v3.oas.models.security.SecurityScheme.Type.APIKEY)
                        .in(io.swagger.v3.oas.models.security.SecurityScheme.In.HEADER)
                        .name("X-API-Key")
                        .description("""
                            API Key authentication for internal services.

                            Used for service-to-service communication.
                            Include the key in the X-API-Key header:
                            `X-API-Key: <your-api-key>`
                            """)));
    }

    private String buildDescription(EnvironmentInfo envInfo) {
        String envWarning = "";
        if (envInfo.name.equals("PRODUCTION") || envInfo.name.equals("LIVE")) {
            envWarning = """

                > **WARNING: This is the %s environment. Exercise caution when testing endpoints.**

                """.formatted(envInfo.name);
        } else if (!envInfo.name.equals("LOCAL") && !envInfo.name.equals("DEV")) {
            envWarning = """

                > **Note: You are currently viewing the %s environment API documentation.**

                """.formatted(envInfo.displayName);
        }

        return """
            ## Authentication & Authorization Service
            %s
            **Environment:** %s (%s)

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

            ### Environment-Specific Notes
            | Environment | Description | Database Port | Redis Port |
            |------------|-------------|---------------|------------|
            | LOCAL | Local development/testing | 3308 | 6379 |
            | DEV | Development environment | 3318 | 6389 |
            | QA | Quality Assurance | 3328 | 6399 |
            | UAT1-3 | User Acceptance Testing | 3338-3358 | 6409-6429 |
            | STAGING | Pre-production staging | 3368 | 6439 |
            | PRODUCTION | Production environment | 3378 | 6449 |
            | LIVE | Live/Hot-standby | 3388 | 6459 |
            """.formatted(envWarning, envInfo.name, envInfo.displayName);
    }

    private List<Server> buildServers(EnvironmentInfo envInfo) {
        List<Server> servers = new ArrayList<>();

        // Current environment server first
        servers.add(new Server()
            .url(envInfo.serverUrl)
            .description(envInfo.displayName + " Server (Current)"));

        // Always add relative path for current context
        servers.add(new Server()
            .url(contextPath)
            .description("Relative Path"));

        // Add other environment servers based on current environment
        String profile = getActiveEnvironment().toLowerCase();

        if (!profile.equals("production") && !profile.equals("live")) {
            // Non-production environments can see production server
            servers.add(new Server()
                .url("https://api.quckapp.com/auth")
                .description("Production Server"));
        }

        if (profile.equals("local") || profile.equals("dev")) {
            // Dev/Local can see staging
            servers.add(new Server()
                .url("https://staging-api.quckapp.com/auth")
                .description("Staging Server"));
        }

        return servers;
    }

    private List<Tag> buildTags() {
        return Arrays.asList(
            new Tag().name("Authentication").description("User authentication endpoints including login, registration, and password management"),
            new Tag().name("Token Management").description("JWT token operations - refresh, validate, and revoke tokens"),
            new Tag().name("Two-Factor Authentication").description("2FA setup, verification, and backup code management"),
            new Tag().name("Phone Authentication").description("Phone-based OTP authentication for SMS login"),
            new Tag().name("OAuth2").description("Social login with Google, Apple, Facebook, and GitHub"),
            new Tag().name("Sessions").description("Active session management and device tracking"),
            new Tag().name("User Profiles").description("User profile CRUD operations and settings management"),
            new Tag().name("Devices").description("Device linking, FCM tokens, and push notification management"),
            new Tag().name("Blocked Users").description("User blocking and unblocking operations"),
            new Tag().name("Admin").description("Administrative operations - user banning, role management"),
            new Tag().name("Migration").description("Data migration endpoints for internal use only"),
            new Tag().name("Internal").description("Internal service-to-service endpoints")
        );
    }

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
                "/v1/token/**",
                "/v1/2fa/**",
                "/v1/sessions/**",
                "/v1/users/me/**",
                "/v1/blocked-users/**",
                "/v1/devices/**"
            )
            .pathsToExclude(
                "/v1/token/refresh",
                "/v1/token/validate"
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
                "/v1/admin/**",
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
                "/v1/internal/**",
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
            if (openApi.getPaths() != null) {
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
            }
        };
    }

    /**
     * Environment information holder
     */
    private record EnvironmentInfo(String name, String displayName, String serverUrl, String color) {}
}
