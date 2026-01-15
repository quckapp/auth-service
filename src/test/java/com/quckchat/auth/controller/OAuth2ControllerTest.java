package com.quckapp.auth.controller;

import com.quckapp.auth.domain.repository.OAuthConnectionRepository;
import com.quckapp.auth.security.oauth2.OAuth2Config;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for OAuth2Controller
 */
@ExtendWith(MockitoExtension.class)
class OAuth2ControllerTest {

    @Mock
    private OAuth2Config oAuth2Config;

    @Mock
    private OAuthConnectionRepository oauthConnectionRepository;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        OAuth2Controller controller = new OAuth2Controller(oAuth2Config, oauthConnectionRepository);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Nested
    @DisplayName("Get Providers Tests")
    class GetProvidersTests {

        @Test
        @DisplayName("should return all available OAuth2 providers")
        void shouldReturnAllAvailableProviders() throws Exception {
            when(oAuth2Config.getFrontendCallbackUrl()).thenReturn("http://localhost:3000/auth/callback");

            mockMvc.perform(get("/v1/oauth2/providers"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.providers").isArray())
                    .andExpect(jsonPath("$.providers.length()").value(4))
                    .andExpect(jsonPath("$.providers[0].name").value("google"))
                    .andExpect(jsonPath("$.providers[0].displayName").value("Google"))
                    .andExpect(jsonPath("$.providers[0].authorizationUrl").value("/oauth2/authorize/google"))
                    .andExpect(jsonPath("$.providers[0].icon").value("google"))
                    .andExpect(jsonPath("$.providers[1].name").value("facebook"))
                    .andExpect(jsonPath("$.providers[2].name").value("github"))
                    .andExpect(jsonPath("$.providers[3].name").value("apple"))
                    .andExpect(jsonPath("$.callbackUrl").value("http://localhost:3000/auth/callback"));

            verify(oAuth2Config).getFrontendCallbackUrl();
        }

        @Test
        @DisplayName("should include correct authorization URLs for all providers")
        void shouldIncludeCorrectAuthorizationUrls() throws Exception {
            when(oAuth2Config.getFrontendCallbackUrl()).thenReturn("http://localhost:3000/callback");

            mockMvc.perform(get("/v1/oauth2/providers"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.providers[0].authorizationUrl").value("/oauth2/authorize/google"))
                    .andExpect(jsonPath("$.providers[1].authorizationUrl").value("/oauth2/authorize/facebook"))
                    .andExpect(jsonPath("$.providers[2].authorizationUrl").value("/oauth2/authorize/github"))
                    .andExpect(jsonPath("$.providers[3].authorizationUrl").value("/oauth2/authorize/apple"));
        }
    }

    @Nested
    @DisplayName("Get Linked Providers Tests")
    class GetLinkedProvidersTests {

        @Test
        @DisplayName("should return linked providers for authenticated user")
        void shouldReturnLinkedProvidersForAuthenticatedUser() throws Exception {
            mockMvc.perform(get("/v1/oauth2/linked")
                            .header("Authorization", "Bearer valid-token"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.linkedProviders").isArray())
                    .andExpect(jsonPath("$.linkedProviders").isEmpty());
        }

        @Test
        @DisplayName("should return empty list when no providers linked")
        void shouldReturnEmptyListWhenNoProvidersLinked() throws Exception {
            mockMvc.perform(get("/v1/oauth2/linked")
                            .header("Authorization", "Bearer another-token"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.linkedProviders").isEmpty());
        }
    }

    @Nested
    @DisplayName("Get Authorization URL Tests")
    class GetAuthorizationUrlTests {

        @Test
        @DisplayName("should return authorization URL for google provider")
        void shouldReturnAuthorizationUrlForGoogle() throws Exception {
            when(oAuth2Config.getFrontendCallbackUrl()).thenReturn("http://localhost:3000/callback");

            mockMvc.perform(get("/v1/oauth2/authorize/google"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.provider").value("google"))
                    .andExpect(jsonPath("$.authorizationUrl").value("/oauth2/authorize/google"))
                    .andExpect(jsonPath("$.redirectUri").value("http://localhost:3000/callback"));
        }

        @Test
        @DisplayName("should return authorization URL for facebook provider")
        void shouldReturnAuthorizationUrlForFacebook() throws Exception {
            when(oAuth2Config.getFrontendCallbackUrl()).thenReturn("http://localhost:3000/callback");

            mockMvc.perform(get("/v1/oauth2/authorize/facebook"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.provider").value("facebook"))
                    .andExpect(jsonPath("$.authorizationUrl").value("/oauth2/authorize/facebook"));
        }

        @Test
        @DisplayName("should return authorization URL for github provider")
        void shouldReturnAuthorizationUrlForGithub() throws Exception {
            when(oAuth2Config.getFrontendCallbackUrl()).thenReturn("http://localhost:3000/callback");

            mockMvc.perform(get("/v1/oauth2/authorize/github"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.provider").value("github"))
                    .andExpect(jsonPath("$.authorizationUrl").value("/oauth2/authorize/github"));
        }

        @Test
        @DisplayName("should return authorization URL for apple provider")
        void shouldReturnAuthorizationUrlForApple() throws Exception {
            when(oAuth2Config.getFrontendCallbackUrl()).thenReturn("http://localhost:3000/callback");

            mockMvc.perform(get("/v1/oauth2/authorize/apple"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.provider").value("apple"))
                    .andExpect(jsonPath("$.authorizationUrl").value("/oauth2/authorize/apple"));
        }

        @Test
        @DisplayName("should use custom redirect URI when provided")
        void shouldUseCustomRedirectUriWhenProvided() throws Exception {
            String customRedirectUri = "http://myapp.com/oauth/callback";

            mockMvc.perform(get("/v1/oauth2/authorize/google")
                            .param("redirectUri", customRedirectUri))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.provider").value("google"))
                    .andExpect(jsonPath("$.authorizationUrl").value("/oauth2/authorize/google?redirect_uri=" + customRedirectUri))
                    .andExpect(jsonPath("$.redirectUri").value(customRedirectUri));
        }

        @Test
        @DisplayName("should normalize provider name to lowercase")
        void shouldNormalizeProviderNameToLowercase() throws Exception {
            when(oAuth2Config.getFrontendCallbackUrl()).thenReturn("http://localhost:3000/callback");

            mockMvc.perform(get("/v1/oauth2/authorize/GOOGLE"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.provider").value("GOOGLE"))
                    .andExpect(jsonPath("$.authorizationUrl").value("/oauth2/authorize/google"));
        }

        @Test
        @DisplayName("should handle mixed case provider name")
        void shouldHandleMixedCaseProviderName() throws Exception {
            when(oAuth2Config.getFrontendCallbackUrl()).thenReturn("http://localhost:3000/callback");

            mockMvc.perform(get("/v1/oauth2/authorize/GitHub"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.authorizationUrl").value("/oauth2/authorize/github"));
        }

        @Test
        @DisplayName("should use default redirect URI when none provided")
        void shouldUseDefaultRedirectUriWhenNoneProvided() throws Exception {
            when(oAuth2Config.getFrontendCallbackUrl()).thenReturn("http://default.callback.com");

            mockMvc.perform(get("/v1/oauth2/authorize/google"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.redirectUri").value("http://default.callback.com"));

            verify(oAuth2Config).getFrontendCallbackUrl();
        }
    }
}
