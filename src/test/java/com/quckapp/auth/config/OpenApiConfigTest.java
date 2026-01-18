package com.quckapp.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for OpenApiConfig
 */
class OpenApiConfigTest {

    private OpenApiConfig openApiConfig;

    @BeforeEach
    void setUp() {
        openApiConfig = new OpenApiConfig();
    }

    @Nested
    @DisplayName("GroupedOpenApi Bean Tests")
    class GroupedOpenApiBeanTests {

        @Test
        @DisplayName("should create publicApi bean with correct configuration")
        void shouldCreatePublicApiBean() {
            GroupedOpenApi publicApi = openApiConfig.publicApi();

            assertThat(publicApi).isNotNull();
            assertThat(publicApi.getGroup()).isEqualTo("1. Public");
            assertThat(publicApi.getPathsToMatch()).contains(
                    "/v1/register",
                    "/v1/login",
                    "/v1/login/2fa"
            );
        }

        @Test
        @DisplayName("should create authenticatedApi bean with correct configuration")
        void shouldCreateAuthenticatedApiBean() {
            GroupedOpenApi authenticatedApi = openApiConfig.authenticatedApi();

            assertThat(authenticatedApi).isNotNull();
            assertThat(authenticatedApi.getGroup()).isEqualTo("2. Authenticated");
            assertThat(authenticatedApi.getPathsToMatch()).contains(
                    "/v1/logout",
                    "/v1/password/change",
                    "/v1/2fa/**",
                    "/v1/sessions/**"
            );
        }

        @Test
        @DisplayName("should create userManagementApi bean with correct configuration")
        void shouldCreateUserManagementApiBean() {
            GroupedOpenApi userManagementApi = openApiConfig.userManagementApi();

            assertThat(userManagementApi).isNotNull();
            assertThat(userManagementApi.getGroup()).isEqualTo("3. User Management");
            assertThat(userManagementApi.getPathsToMatch()).containsExactly("/v1/users/**");
        }

        @Test
        @DisplayName("should create adminApi bean with correct configuration")
        void shouldCreateAdminApiBean() {
            GroupedOpenApi adminApi = openApiConfig.adminApi();

            assertThat(adminApi).isNotNull();
            assertThat(adminApi.getGroup()).isEqualTo("4. Admin");
            assertThat(adminApi.getPathsToMatch()).containsExactly("/v1/users/admin/**");
        }

        @Test
        @DisplayName("should create internalApi bean with correct configuration")
        void shouldCreateInternalApiBean() {
            GroupedOpenApi internalApi = openApiConfig.internalApi();

            assertThat(internalApi).isNotNull();
            assertThat(internalApi.getGroup()).isEqualTo("5. Internal");
            assertThat(internalApi.getPathsToMatch()).contains("/v1/users/internal/**", "/v1/migration/**");
        }

        @Test
        @DisplayName("should create allApi bean with correct configuration")
        void shouldCreateAllApiBean() {
            GroupedOpenApi allApi = openApiConfig.allApi();

            assertThat(allApi).isNotNull();
            assertThat(allApi.getGroup()).isEqualTo("0. All Endpoints");
            assertThat(allApi.getPathsToMatch()).containsExactly("/v1/**");
        }
    }

    @Nested
    @DisplayName("CustomOpenAPI Bean Tests")
    class CustomOpenAPIBeanTests {

        @Test
        @DisplayName("should create customOpenAPI bean with components")
        void shouldCreateCustomOpenAPIBean() {
            OpenAPI openAPI = openApiConfig.customOpenAPI();

            assertThat(openAPI).isNotNull();
            assertThat(openAPI.getComponents()).isNotNull();
            // Info is set via @OpenAPIDefinition annotation, not programmatically
        }

        @Test
        @DisplayName("should configure bearer auth security scheme")
        void shouldConfigureBearerAuthSecurityScheme() {
            OpenAPI openAPI = openApiConfig.customOpenAPI();

            assertThat(openAPI.getComponents()).isNotNull();
            assertThat(openAPI.getComponents().getSecuritySchemes()).isNotNull();

            SecurityScheme bearerAuth = openAPI.getComponents().getSecuritySchemes().get("bearerAuth");
            assertThat(bearerAuth).isNotNull();
            assertThat(bearerAuth.getType()).isEqualTo(SecurityScheme.Type.HTTP);
            assertThat(bearerAuth.getScheme()).isEqualTo("bearer");
            assertThat(bearerAuth.getBearerFormat()).isEqualTo("JWT");
        }

        @Test
        @DisplayName("should configure API key security scheme")
        void shouldConfigureApiKeySecurityScheme() {
            OpenAPI openAPI = openApiConfig.customOpenAPI();

            assertThat(openAPI.getComponents()).isNotNull();
            assertThat(openAPI.getComponents().getSecuritySchemes()).isNotNull();

            SecurityScheme apiKey = openAPI.getComponents().getSecuritySchemes().get("apiKey");
            assertThat(apiKey).isNotNull();
            assertThat(apiKey.getType()).isEqualTo(SecurityScheme.Type.APIKEY);
            assertThat(apiKey.getIn()).isEqualTo(SecurityScheme.In.HEADER);
            assertThat(apiKey.getName()).isEqualTo("X-API-Key");
        }
    }

    @Nested
    @DisplayName("OpenApiCustomizer Bean Tests")
    class OpenApiCustomizerBeanTests {

        @Test
        @DisplayName("should create globalResponseCustomizer bean")
        void shouldCreateGlobalResponseCustomizerBean() {
            OpenApiCustomizer customizer = openApiConfig.globalResponseCustomizer();

            assertThat(customizer).isNotNull();
        }

        @Test
        @DisplayName("should customize OpenAPI with global responses when paths exist")
        void shouldCustomizeOpenAPIWithGlobalResponses() {
            OpenApiCustomizer customizer = openApiConfig.globalResponseCustomizer();

            // Create an OpenAPI with paths and a successful response
            OpenAPI openAPI = new OpenAPI();
            io.swagger.v3.oas.models.Paths paths = new io.swagger.v3.oas.models.Paths();
            io.swagger.v3.oas.models.PathItem pathItem = new io.swagger.v3.oas.models.PathItem();
            io.swagger.v3.oas.models.Operation operation = new io.swagger.v3.oas.models.Operation();
            io.swagger.v3.oas.models.responses.ApiResponses responses = new io.swagger.v3.oas.models.responses.ApiResponses();
            io.swagger.v3.oas.models.responses.ApiResponse successResponse = new io.swagger.v3.oas.models.responses.ApiResponse();
            successResponse.setDescription("Success");
            responses.addApiResponse("200", successResponse);
            operation.setResponses(responses);
            pathItem.setGet(operation);
            paths.addPathItem("/test", pathItem);
            openAPI.setPaths(paths);

            // Apply the customizer
            customizer.customise(openAPI);

            // Verify rate limit headers were added
            assertThat(successResponse.getHeaders()).isNotNull();
            assertThat(successResponse.getHeaders()).containsKey("X-RateLimit-Limit");
            assertThat(successResponse.getHeaders()).containsKey("X-RateLimit-Remaining");
            assertThat(successResponse.getHeaders()).containsKey("X-RateLimit-Reset");
        }

        @Test
        @DisplayName("should handle OpenAPI with empty paths")
        void shouldHandleOpenAPIWithEmptyPaths() {
            OpenApiCustomizer customizer = openApiConfig.globalResponseCustomizer();
            OpenAPI openAPI = new OpenAPI();
            openAPI.setPaths(new io.swagger.v3.oas.models.Paths());

            // Should not throw exception
            customizer.customise(openAPI);

            assertThat(openAPI).isNotNull();
        }
    }
}
