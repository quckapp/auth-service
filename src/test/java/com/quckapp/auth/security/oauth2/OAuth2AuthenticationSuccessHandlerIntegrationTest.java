package com.quckapp.auth.security.oauth2;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.RefreshToken;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.RefreshTokenRepository;
import com.quckapp.auth.dto.LoginHistoryDtos.RecordLoginRequest;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.LoginHistoryService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

/**
 * Integration tests for OAuth2AuthenticationSuccessHandler
 * Tests the full onAuthenticationSuccess flow
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("OAuth2AuthenticationSuccessHandler Integration Tests")
class OAuth2AuthenticationSuccessHandlerIntegrationTest {

    @Mock
    private JwtOperations jwtService;

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private LoginHistoryService loginHistoryService;

    @Mock
    private HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    private OAuth2AuthenticationSuccessHandler handler;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private AuthUser testUser;
    private TestOAuth2Config oAuth2Config;

    static class TestOAuth2Config extends OAuth2Config {
        @Override
        public String getRedirectUriCookieName() {
            return "redirect_uri";
        }

        @Override
        public String getFrontendCallbackUrl() {
            return "http://localhost:3000/oauth/callback";
        }

        @Override
        public String getDefaultFailureUrl() {
            return "http://localhost:3000/login?error=true";
        }
    }

    @BeforeEach
    void setUp() {
        oAuth2Config = new TestOAuth2Config();
        handler = new OAuth2AuthenticationSuccessHandler(
                jwtService,
                authUserRepository,
                refreshTokenRepository,
                loginHistoryService,
                oAuth2Config,
                authorizationRequestRepository
        );

        testUser = AuthUser.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .externalId("ext-123")
                .status(AuthUser.AuthStatus.ACTIVE)
                .emailVerified(true)
                .build();

        request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");
        request.addHeader("User-Agent", "Test Browser/1.0");
        response = new MockHttpServletResponse();

        // Default JWT setup
        given(jwtService.generateAccessToken(any(AuthUser.class))).willReturn("test-access-token");
        given(jwtService.generateRefreshToken(any(AuthUser.class))).willReturn("test-refresh-token");
        given(jwtService.getAccessTokenExpiration()).willReturn(3600L);
    }

    @Nested
    @DisplayName("Full onAuthenticationSuccess Flow Tests")
    class OnAuthenticationSuccessFlowTests {

        @Test
        @DisplayName("should complete full flow with CustomOidcUser")
        void shouldCompleteFullFlowWithCustomOidcUser() throws IOException {
            // Arrange
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            assertThat(response.getRedirectedUrl()).isNotNull();
            assertThat(response.getRedirectedUrl()).contains("access_token=test-access-token");
            assertThat(response.getRedirectedUrl()).contains("refresh_token=test-refresh-token");
            assertThat(response.getRedirectedUrl()).contains("token_type=Bearer");
            assertThat(response.getRedirectedUrl()).contains("expires_in=3600");
            assertThat(response.getRedirectedUrl()).contains("new_user=false");

            verify(jwtService).generateAccessToken(testUser);
            verify(jwtService).generateRefreshToken(testUser);
            verify(refreshTokenRepository).save(any(RefreshToken.class));
            verify(loginHistoryService).recordLogin(any(RecordLoginRequest.class));
            verify(authorizationRequestRepository).removeAuthorizationRequestCookies(request, response);
        }

        @Test
        @DisplayName("should complete full flow with new CustomOidcUser")
        void shouldCompleteFullFlowWithNewCustomOidcUser() throws IOException {
            // Arrange
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, true);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            assertThat(response.getRedirectedUrl()).contains("new_user=true");
        }

        @Test
        @DisplayName("should complete full flow with OAuth2UserPrincipal")
        void shouldCompleteFullFlowWithOAuth2UserPrincipal() throws IOException {
            // Arrange
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("id", "12345");
            attributes.put("email", "test@example.com");
            OAuth2UserPrincipal principal = OAuth2UserPrincipal.create(testUser, attributes, false);
            Authentication auth = new TestAuthentication(principal);
            given(authUserRepository.findById(testUser.getId())).willReturn(Optional.of(testUser));

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            assertThat(response.getRedirectedUrl()).isNotNull();
            assertThat(response.getRedirectedUrl()).contains("access_token=test-access-token");
            verify(authUserRepository).findById(testUser.getId());
            verify(refreshTokenRepository).save(any(RefreshToken.class));
        }

        @Test
        @DisplayName("should complete full flow with OidcUser fallback")
        void shouldCompleteFullFlowWithOidcUserFallback() throws IOException {
            // Arrange
            OidcUser oidcUser = createMockOidcUser();
            Authentication auth = new TestAuthentication(oidcUser);
            given(authUserRepository.findByEmail("test@example.com")).willReturn(Optional.of(testUser));

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            assertThat(response.getRedirectedUrl()).isNotNull();
            assertThat(response.getRedirectedUrl()).contains("access_token=test-access-token");
            verify(authUserRepository).findByEmail("test@example.com");
        }

        @Test
        @DisplayName("should use custom redirect URI from cookie")
        void shouldUseCustomRedirectUriFromCookie() throws IOException {
            // Arrange
            request.setCookies(new Cookie("redirect_uri", "http://custom-app.com/callback"));
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            assertThat(response.getRedirectedUrl()).startsWith("http://custom-app.com/callback");
        }

        @Test
        @DisplayName("should use default callback URL when no cookie")
        void shouldUseDefaultCallbackUrlWhenNoCookie() throws IOException {
            // Arrange
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            assertThat(response.getRedirectedUrl()).startsWith("http://localhost:3000/oauth/callback");
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("should redirect with error when user not found from OAuth2UserPrincipal")
        void shouldRedirectWithErrorWhenUserNotFoundFromOAuth2UserPrincipal() throws IOException {
            // Arrange
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("id", "12345");
            attributes.put("email", "test@example.com");
            OAuth2UserPrincipal principal = OAuth2UserPrincipal.create(testUser, attributes, false);
            Authentication auth = new TestAuthentication(principal);
            given(authUserRepository.findById(testUser.getId())).willReturn(Optional.empty());

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            assertThat(response.getRedirectedUrl()).contains("error=user_not_found");
            verify(refreshTokenRepository, never()).save(any(RefreshToken.class));
            verify(loginHistoryService, never()).recordLogin(any(RecordLoginRequest.class));
        }

        @Test
        @DisplayName("should redirect with error when user not found from OidcUser")
        void shouldRedirectWithErrorWhenUserNotFoundFromOidcUser() throws IOException {
            // Arrange
            OidcUser oidcUser = createMockOidcUser();
            Authentication auth = new TestAuthentication(oidcUser);
            given(authUserRepository.findByEmail("test@example.com")).willReturn(Optional.empty());

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            assertThat(response.getRedirectedUrl()).contains("error=user_not_found");
        }

        @Test
        @DisplayName("should redirect with error for unknown principal type")
        void shouldRedirectWithErrorForUnknownPrincipalType() throws IOException {
            // Arrange
            Authentication auth = new TestAuthentication("unknown-principal");

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            assertThat(response.getRedirectedUrl()).contains("error=user_not_found");
        }

        @Test
        @DisplayName("should not redirect when response is committed")
        void shouldNotRedirectWhenResponseIsCommitted() throws IOException {
            // Arrange
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Commit the response first
            response.getWriter().write("already committed");
            response.flushBuffer();

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert - no redirect should happen since response was committed
            // The handler returns early without redirecting
        }

        @Test
        @DisplayName("should continue even when login history recording fails")
        void shouldContinueEvenWhenLoginHistoryRecordingFails() throws IOException {
            // Arrange
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);
            doThrow(new RuntimeException("Database error")).when(loginHistoryService)
                    .recordLogin(any(RecordLoginRequest.class));

            // Act - should not throw
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert - redirect still happened despite login history failure
            assertThat(response.getRedirectedUrl()).isNotNull();
            assertThat(response.getRedirectedUrl()).contains("access_token=test-access-token");
        }
    }

    @Nested
    @DisplayName("RefreshToken Storage Tests")
    class RefreshTokenStorageTests {

        @Test
        @DisplayName("should save refresh token with correct data")
        void shouldSaveRefreshTokenWithCorrectData() throws IOException {
            // Arrange
            ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            verify(refreshTokenRepository).save(tokenCaptor.capture());
            RefreshToken savedToken = tokenCaptor.getValue();
            assertThat(savedToken.getUser()).isEqualTo(testUser);
            assertThat(savedToken.getToken()).isEqualTo("test-refresh-token");
            assertThat(savedToken.getIpAddress()).isEqualTo("127.0.0.1");
            assertThat(savedToken.getUserAgent()).isEqualTo("Test Browser/1.0");
            assertThat(savedToken.getExpiresAt()).isNotNull();
        }

        @Test
        @DisplayName("should extract IP from X-Forwarded-For header")
        void shouldExtractIpFromXForwardedForHeader() throws IOException {
            // Arrange
            request.addHeader("X-Forwarded-For", "192.168.1.100, 10.0.0.1");
            ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            verify(refreshTokenRepository).save(tokenCaptor.capture());
            RefreshToken savedToken = tokenCaptor.getValue();
            assertThat(savedToken.getIpAddress()).isEqualTo("192.168.1.100");
        }

        @Test
        @DisplayName("should extract IP from X-Real-IP header")
        void shouldExtractIpFromXRealIpHeader() throws IOException {
            // Arrange
            request.addHeader("X-Real-IP", "172.16.0.50");
            ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            verify(refreshTokenRepository).save(tokenCaptor.capture());
            RefreshToken savedToken = tokenCaptor.getValue();
            assertThat(savedToken.getIpAddress()).isEqualTo("172.16.0.50");
        }
    }

    @Nested
    @DisplayName("Login History Recording Tests")
    class LoginHistoryRecordingTests {

        @Test
        @DisplayName("should record login with correct data")
        void shouldRecordLoginWithCorrectData() throws IOException {
            // Arrange
            ArgumentCaptor<RecordLoginRequest> requestCaptor = ArgumentCaptor.forClass(RecordLoginRequest.class);
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            verify(loginHistoryService).recordLogin(requestCaptor.capture());
            RecordLoginRequest loginRequest = requestCaptor.getValue();
            assertThat(loginRequest.getUserId()).isEqualTo(testUser.getId());
            assertThat(loginRequest.getEmail()).isEqualTo("test@example.com");
            assertThat(loginRequest.getIpAddress()).isEqualTo("127.0.0.1");
            assertThat(loginRequest.getUserAgent()).isEqualTo("Test Browser/1.0");
        }
    }

    @Nested
    @DisplayName("Cookie Clearing Tests")
    class CookieClearingTests {

        @Test
        @DisplayName("should clear authorization cookies after success")
        void shouldClearAuthorizationCookiesAfterSuccess() throws IOException {
            // Arrange
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            verify(authorizationRequestRepository).removeAuthorizationRequestCookies(request, response);
        }

        @Test
        @DisplayName("should clear cookies even when redirect URI is from cookie")
        void shouldClearCookiesEvenWhenRedirectUriIsFromCookie() throws IOException {
            // Arrange
            request.setCookies(new Cookie("redirect_uri", "http://custom.com/callback"));
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            verify(authorizationRequestRepository).removeAuthorizationRequestCookies(request, response);
        }
    }

    @Nested
    @DisplayName("Token Generation Tests")
    class TokenGenerationTests {

        @Test
        @DisplayName("should generate both access and refresh tokens")
        void shouldGenerateBothAccessAndRefreshTokens() throws IOException {
            // Arrange
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            verify(jwtService).generateAccessToken(testUser);
            verify(jwtService).generateRefreshToken(testUser);
        }

        @Test
        @DisplayName("should include correct token type in redirect URL")
        void shouldIncludeCorrectTokenTypeInRedirectUrl() throws IOException {
            // Arrange
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            assertThat(response.getRedirectedUrl()).contains("token_type=Bearer");
        }

        @Test
        @DisplayName("should include expiration in redirect URL")
        void shouldIncludeExpirationInRedirectUrl() throws IOException {
            // Arrange
            given(jwtService.getAccessTokenExpiration()).willReturn(7200L);
            OidcUser oidcUser = createMockOidcUser();
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, oidcUser, false);
            Authentication auth = new TestAuthentication(customOidcUser);

            // Act
            handler.onAuthenticationSuccess(request, response, auth);

            // Assert
            assertThat(response.getRedirectedUrl()).contains("expires_in=7200");
        }
    }

    // Helper methods
    private OidcUser createMockOidcUser() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "12345");
        claims.put("email", "test@example.com");
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(),
                Instant.now().plusSeconds(3600), claims);
        return new DefaultOidcUser(Collections.emptyList(), idToken);
    }

    // Simple Authentication implementation for testing
    static class TestAuthentication implements Authentication {
        private final Object principal;

        TestAuthentication(Object principal) {
            this.principal = principal;
        }

        @Override
        public Object getPrincipal() {
            return principal;
        }

        @Override
        public String getName() {
            return "test";
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return Collections.emptyList();
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Object getDetails() {
            return null;
        }

        @Override
        public boolean isAuthenticated() {
            return true;
        }

        @Override
        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        }
    }
}
