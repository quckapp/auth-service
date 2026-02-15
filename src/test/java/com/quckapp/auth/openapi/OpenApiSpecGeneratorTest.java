package com.quckapp.auth.openapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.quckapp.auth.config.OpenApiConfig;
import io.swagger.v3.core.util.Json;
import io.swagger.v3.core.util.Yaml;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.env.Environment;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileWriter;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Generates OpenAPI specification from controller annotations.
 * This provides a basic spec without starting the full Spring context.
 */
class OpenApiSpecGeneratorTest {

    private OpenAPI openAPI;
    private OpenApiConfig openApiConfig;

    private static final List<Class<?>> CONTROLLERS = List.of(
            com.quckapp.auth.controller.AuthController.class,
            com.quckapp.auth.controller.TokenController.class,
            com.quckapp.auth.controller.TwoFactorController.class,
            com.quckapp.auth.controller.SessionController.class,
            com.quckapp.auth.controller.DevicesController.class,
            com.quckapp.auth.controller.BlockedUsersController.class,
            com.quckapp.auth.controller.AdminController.class,
            com.quckapp.auth.controller.InternalController.class,
            com.quckapp.auth.controller.UserProfileController.class,
            com.quckapp.auth.controller.PhoneAuthController.class,
            com.quckapp.auth.controller.OAuth2Controller.class,
            com.quckapp.auth.controller.MigrationController.class
    );

    @BeforeEach
    void setUp() {
        // Create mock environment
        Environment environment = Mockito.mock(Environment.class);
        when(environment.getActiveProfiles()).thenReturn(new String[]{"local"});

        openApiConfig = new OpenApiConfig(environment);
        ReflectionTestUtils.setField(openApiConfig, "serverPort", 8081);
        ReflectionTestUtils.setField(openApiConfig, "contextPath", "/api/auth");

        openAPI = openApiConfig.customOpenAPI();

        // Override info for spec generation
        openAPI.setInfo(new Info()
                .title("QuckApp Auth Service API")
                .version("1.0.0")
                .description("Authentication and Authorization Service API for QuckApp")
                .contact(new Contact()
                        .name("QuckApp Team")
                        .email("support@quckapp.com")
                        .url("https://quckapp.com"))
                .license(new License()
                        .name("MIT License")
                        .url("https://opensource.org/licenses/MIT")));

        // Set up servers
        openAPI.setServers(List.of(
                new Server().url("/api/auth").description("Auth Service Base Path"),
                new Server().url("http://localhost:8081/api/auth").description("Local Development"),
                new Server().url("https://api.quckapp.com/auth").description("Production")
        ));

        // Set up tags
        openAPI.setTags(List.of(
                new Tag().name("Authentication").description("User authentication endpoints"),
                new Tag().name("Token Management").description("JWT token operations"),
                new Tag().name("Two-Factor Authentication").description("2FA setup and verification"),
                new Tag().name("Phone Authentication").description("Phone-based OTP authentication"),
                new Tag().name("OAuth2").description("Social login providers"),
                new Tag().name("Sessions").description("Session management"),
                new Tag().name("User Profiles").description("User profile operations"),
                new Tag().name("Devices").description("Device management"),
                new Tag().name("Blocked Users").description("User blocking operations"),
                new Tag().name("Admin").description("Administrative operations"),
                new Tag().name("Internal").description("Service-to-service endpoints"),
                new Tag().name("Migration").description("Data migration endpoints")
        ));

        // Initialize paths
        openAPI.setPaths(new Paths());
    }

    @Test
    @DisplayName("should generate OpenAPI spec from controllers")
    void shouldGenerateOpenApiSpec() throws Exception {
        // Scan controllers and build paths
        for (Class<?> controller : CONTROLLERS) {
            scanController(controller);
        }

        // Verify spec was generated
        assertThat(openAPI.getPaths()).isNotEmpty();

        // Write JSON spec
        String jsonSpec = Json.pretty(openAPI);
        Path jsonPath = Path.of("target/openapi/auth-service-api.json");
        Files.createDirectories(jsonPath.getParent());
        Files.writeString(jsonPath, jsonSpec);

        // Write YAML spec
        String yamlSpec = Yaml.pretty(openAPI);
        Path yamlPath = Path.of("target/openapi/auth-service-api.yaml");
        Files.writeString(yamlPath, yamlSpec);

        System.out.println("OpenAPI specs generated:");
        System.out.println("  - " + jsonPath.toAbsolutePath());
        System.out.println("  - " + yamlPath.toAbsolutePath());
        System.out.println("Total endpoints: " + countEndpoints());
    }

    @Test
    @DisplayName("should list all endpoints")
    void shouldListAllEndpoints() {
        List<String> endpoints = new ArrayList<>();

        for (Class<?> controller : CONTROLLERS) {
            String basePath = getBasePath(controller);
            String controllerName = controller.getSimpleName();

            for (Method method : controller.getDeclaredMethods()) {
                String httpMethod = null;
                String path = basePath;

                if (method.isAnnotationPresent(GetMapping.class)) {
                    httpMethod = "GET";
                    path += getPath(method.getAnnotation(GetMapping.class).value());
                } else if (method.isAnnotationPresent(PostMapping.class)) {
                    httpMethod = "POST";
                    path += getPath(method.getAnnotation(PostMapping.class).value());
                } else if (method.isAnnotationPresent(PutMapping.class)) {
                    httpMethod = "PUT";
                    path += getPath(method.getAnnotation(PutMapping.class).value());
                } else if (method.isAnnotationPresent(DeleteMapping.class)) {
                    httpMethod = "DELETE";
                    path += getPath(method.getAnnotation(DeleteMapping.class).value());
                } else if (method.isAnnotationPresent(PatchMapping.class)) {
                    httpMethod = "PATCH";
                    path += getPath(method.getAnnotation(PatchMapping.class).value());
                }

                if (httpMethod != null) {
                    endpoints.add(String.format("%-7s %-45s %s", httpMethod, path, controllerName));
                }
            }
        }

        Collections.sort(endpoints);

        System.out.println("\n=== Auth Service API Endpoints ===\n");
        System.out.println(String.format("%-7s %-45s %s", "METHOD", "PATH", "CONTROLLER"));
        System.out.println("-".repeat(80));
        endpoints.forEach(System.out::println);
        System.out.println("\nTotal: " + endpoints.size() + " endpoints");

        assertThat(endpoints).hasSizeGreaterThan(100);
    }

    private void scanController(Class<?> controller) {
        String basePath = getBasePath(controller);
        String tag = getTagFromController(controller);

        for (Method method : controller.getDeclaredMethods()) {
            if (method.isAnnotationPresent(GetMapping.class)) {
                addOperation(basePath, method.getAnnotation(GetMapping.class).value(),
                        PathItem.HttpMethod.GET, method, tag);
            } else if (method.isAnnotationPresent(PostMapping.class)) {
                addOperation(basePath, method.getAnnotation(PostMapping.class).value(),
                        PathItem.HttpMethod.POST, method, tag);
            } else if (method.isAnnotationPresent(PutMapping.class)) {
                addOperation(basePath, method.getAnnotation(PutMapping.class).value(),
                        PathItem.HttpMethod.PUT, method, tag);
            } else if (method.isAnnotationPresent(DeleteMapping.class)) {
                addOperation(basePath, method.getAnnotation(DeleteMapping.class).value(),
                        PathItem.HttpMethod.DELETE, method, tag);
            } else if (method.isAnnotationPresent(PatchMapping.class)) {
                addOperation(basePath, method.getAnnotation(PatchMapping.class).value(),
                        PathItem.HttpMethod.PATCH, method, tag);
            }
        }
    }

    private String getBasePath(Class<?> controller) {
        if (controller.isAnnotationPresent(RequestMapping.class)) {
            String[] values = controller.getAnnotation(RequestMapping.class).value();
            if (values.length > 0) {
                return values[0];
            }
        }
        return "";
    }

    private String getTagFromController(Class<?> controller) {
        String name = controller.getSimpleName().replace("Controller", "");
        return switch (name) {
            case "Auth" -> "Authentication";
            case "Token" -> "Token Management";
            case "TwoFactor" -> "Two-Factor Authentication";
            case "PhoneAuth" -> "Phone Authentication";
            case "OAuth2" -> "OAuth2";
            case "Session" -> "Sessions";
            case "UserProfile" -> "User Profiles";
            case "Devices" -> "Devices";
            case "BlockedUsers" -> "Blocked Users";
            case "Admin" -> "Admin";
            case "Internal" -> "Internal";
            case "Migration" -> "Migration";
            default -> name;
        };
    }

    private void addOperation(String basePath, String[] pathValues, PathItem.HttpMethod httpMethod,
                              Method javaMethod, String tag) {
        String path = basePath + getPath(pathValues);

        PathItem pathItem = openAPI.getPaths().computeIfAbsent(path, k -> new PathItem());

        Operation operation = new Operation()
                .operationId(javaMethod.getName())
                .tags(List.of(tag))
                .summary(generateSummary(javaMethod.getName()))
                .responses(new ApiResponses()
                        .addApiResponse("200", new ApiResponse().description("Success"))
                        .addApiResponse("400", new ApiResponse().description("Bad Request"))
                        .addApiResponse("401", new ApiResponse().description("Unauthorized"))
                        .addApiResponse("500", new ApiResponse().description("Internal Server Error")));

        // Add path parameters
        extractPathParameters(path).forEach(param ->
                operation.addParametersItem(new Parameter()
                        .name(param)
                        .in("path")
                        .required(true)
                        .schema(new Schema<String>().type("string"))));

        // Add request body for POST/PUT/PATCH
        if (httpMethod == PathItem.HttpMethod.POST ||
            httpMethod == PathItem.HttpMethod.PUT ||
            httpMethod == PathItem.HttpMethod.PATCH) {
            operation.setRequestBody(new RequestBody()
                    .content(new Content()
                            .addMediaType("application/json",
                                    new MediaType().schema(new Schema<>().type("object")))));
        }

        switch (httpMethod) {
            case GET -> pathItem.setGet(operation);
            case POST -> pathItem.setPost(operation);
            case PUT -> pathItem.setPut(operation);
            case DELETE -> pathItem.setDelete(operation);
            case PATCH -> pathItem.setPatch(operation);
        }
    }

    private String getPath(String[] values) {
        if (values == null || values.length == 0) {
            return "";
        }
        return values[0].startsWith("/") ? values[0] : "/" + values[0];
    }

    private String generateSummary(String methodName) {
        // Convert camelCase to sentence
        String summary = methodName.replaceAll("([a-z])([A-Z])", "$1 $2");
        return Character.toUpperCase(summary.charAt(0)) + summary.substring(1);
    }

    private List<String> extractPathParameters(String path) {
        List<String> params = new ArrayList<>();
        int start = -1;
        for (int i = 0; i < path.length(); i++) {
            if (path.charAt(i) == '{') {
                start = i + 1;
            } else if (path.charAt(i) == '}' && start >= 0) {
                params.add(path.substring(start, i));
                start = -1;
            }
        }
        return params;
    }

    private int countEndpoints() {
        return openAPI.getPaths().values().stream()
                .mapToInt(pathItem -> {
                    int count = 0;
                    if (pathItem.getGet() != null) count++;
                    if (pathItem.getPost() != null) count++;
                    if (pathItem.getPut() != null) count++;
                    if (pathItem.getDelete() != null) count++;
                    if (pathItem.getPatch() != null) count++;
                    return count;
                })
                .sum();
    }
}
