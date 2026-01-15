package com.quckapp.auth.controller;

import com.quckapp.auth.domain.entity.OAuthConnection.OAuthProvider;
import com.quckapp.auth.domain.repository.OAuthConnectionRepository;
import com.quckapp.auth.security.oauth2.OAuth2Config;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * OAuth2 Controller - Additional OAuth2 endpoints
 */
@RestController
@RequestMapping("/v1/oauth2")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "OAuth2", description = "OAuth2 authentication endpoints")
public class OAuth2Controller {

    private final OAuth2Config oAuth2Config;
    private final OAuthConnectionRepository oauthConnectionRepository;

    /**
     * Get available OAuth2 providers
     */
    @GetMapping("/providers")
    @Operation(summary = "Get available OAuth2 providers")
    public ResponseEntity<ProvidersResponse> getProviders() {
        List<ProviderInfo> providers = Arrays.asList(
                ProviderInfo.builder()
                        .name("google")
                        .displayName("Google")
                        .authorizationUrl("/oauth2/authorize/google")
                        .icon("google")
                        .build(),
                ProviderInfo.builder()
                        .name("facebook")
                        .displayName("Facebook")
                        .authorizationUrl("/oauth2/authorize/facebook")
                        .icon("facebook")
                        .build(),
                ProviderInfo.builder()
                        .name("github")
                        .displayName("GitHub")
                        .authorizationUrl("/oauth2/authorize/github")
                        .icon("github")
                        .build(),
                ProviderInfo.builder()
                        .name("apple")
                        .displayName("Apple")
                        .authorizationUrl("/oauth2/authorize/apple")
                        .icon("apple")
                        .build()
        );

        return ResponseEntity.ok(ProvidersResponse.builder()
                .providers(providers)
                .callbackUrl(oAuth2Config.getFrontendCallbackUrl())
                .build());
    }

    /**
     * Get linked providers for a user (requires auth token)
     */
    @GetMapping("/linked")
    @Operation(summary = "Get linked OAuth2 providers for current user")
    public ResponseEntity<LinkedProvidersResponse> getLinkedProviders(
            @RequestHeader("Authorization") String authHeader) {
        // This would typically extract user ID from JWT and query linked providers
        // For now, returning empty - the AuthService.getActiveSessions includes this info
        return ResponseEntity.ok(LinkedProvidersResponse.builder()
                .linkedProviders(Collections.emptyList())
                .build());
    }

    /**
     * Get authorization URL for a specific provider
     */
    @GetMapping("/authorize/{provider}")
    @Operation(summary = "Get authorization URL for OAuth2 provider")
    public ResponseEntity<AuthorizationUrlResponse> getAuthorizationUrl(
            @PathVariable String provider,
            @RequestParam(required = false) String redirectUri) {

        String baseUrl = "/oauth2/authorize/" + provider.toLowerCase();
        String url = redirectUri != null ? baseUrl + "?redirect_uri=" + redirectUri : baseUrl;

        return ResponseEntity.ok(AuthorizationUrlResponse.builder()
                .provider(provider)
                .authorizationUrl(url)
                .redirectUri(redirectUri != null ? redirectUri : oAuth2Config.getFrontendCallbackUrl())
                .build());
    }

    // ==================== Response DTOs ====================

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class ProvidersResponse {
        private List<ProviderInfo> providers;
        private String callbackUrl;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class ProviderInfo {
        private String name;
        private String displayName;
        private String authorizationUrl;
        private String icon;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class LinkedProvidersResponse {
        private List<String> linkedProviders;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class AuthorizationUrlResponse {
        private String provider;
        private String authorizationUrl;
        private String redirectUri;
    }
}
