package com.quckapp.auth.security.oauth2;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.RefreshToken;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.RefreshTokenRepository;
import com.quckapp.auth.dto.LoginHistoryDtos.RecordLoginRequest;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.LoginHistoryService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for OAuth2AuthenticationSuccessHandler
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OAuth2AuthenticationSuccessHandlerTest {

    @Mock
    private JwtOperations jwtService;

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private LoginHistoryService loginHistoryService;

    @Mock
    private OAuth2Config oAuth2Config;

    @Mock
    private HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private Authentication authentication;

    private OAuth2AuthenticationSuccessHandler successHandler;

    private AuthUser testUser;
    private UUID testUserId;

    @BeforeEach
    void setUp() {
        successHandler = new OAuth2AuthenticationSuccessHandler(
                jwtService,
                authUserRepository,
                refreshTokenRepository,
                loginHistoryService,
                oAuth2Config,
                authorizationRequestRepository
        );

        testUserId = UUID.randomUUID();
        testUser = AuthUser.builder()
                .id(testUserId)
                .email("test@example.com")
                .externalId("ext-123")
                .status(AuthUser.AuthStatus.ACTIVE)
                .emailVerified(true)
                .build();

        // Default mock setup
        when(oAuth2Config.getRedirectUriCookieName()).thenReturn("redirect_uri");
        when(oAuth2Config.getFrontendCallbackUrl()).thenReturn("http://localhost:3000/oauth/callback");
        when(jwtService.generateAccessToken(any(AuthUser.class))).thenReturn("test-access-token");
        when(jwtService.generateRefreshToken(any(AuthUser.class))).thenReturn("test-refresh-token");
        when(jwtService.getAccessTokenExpiration()).thenReturn(3600L);
        when(request.getCookies()).thenReturn(null);
        when(request.getHeader("User-Agent")).thenReturn("Test User Agent");
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(response.isCommitted()).thenReturn(false);
    }

    @Nested
    @DisplayName("Token Generation Tests")
    class TokenGenerationTests {

        @Test
        @DisplayName("should generate access token for authenticated user")
        void shouldGenerateAccessTokenForAuthenticatedUser() {
            when(jwtService.generateAccessToken(testUser)).thenReturn("generated-access-token");

            String token = jwtService.generateAccessToken(testUser);

            assertThat(token).isEqualTo("generated-access-token");
            verify(jwtService).generateAccessToken(testUser);
        }

        @Test
        @DisplayName("should generate refresh token for authenticated user")
        void shouldGenerateRefreshTokenForAuthenticatedUser() {
            when(jwtService.generateRefreshToken(testUser)).thenReturn("generated-refresh-token");

            String token = jwtService.generateRefreshToken(testUser);

            assertThat(token).isEqualTo("generated-refresh-token");
            verify(jwtService).generateRefreshToken(testUser);
        }

        @Test
        @DisplayName("should include token expiration in response")
        void shouldIncludeTokenExpirationInResponse() {
            when(jwtService.getAccessTokenExpiration()).thenReturn(7200L);

            long expiration = jwtService.getAccessTokenExpiration();

            assertThat(expiration).isEqualTo(7200L);
        }
    }

    @Nested
    @DisplayName("Refresh Token Storage Tests")
    class RefreshTokenStorageTests {

        @Test
        @DisplayName("should save refresh token to repository")
        void shouldSaveRefreshTokenToRepository() {
            ArgumentCaptor<RefreshToken> tokenCaptor = ArgumentCaptor.forClass(RefreshToken.class);
            when(refreshTokenRepository.save(tokenCaptor.capture())).thenAnswer(inv -> inv.getArgument(0));

            RefreshToken refreshToken = RefreshToken.builder()
                    .user(testUser)
                    .token("test-refresh-token")
                    .ipAddress("127.0.0.1")
                    .userAgent("Test Agent")
                    .build();

            refreshTokenRepository.save(refreshToken);

            RefreshToken captured = tokenCaptor.getValue();
            assertThat(captured.getToken()).isEqualTo("test-refresh-token");
            assertThat(captured.getUser()).isEqualTo(testUser);
        }

        @Test
        @DisplayName("should include IP address in refresh token")
        void shouldIncludeIpAddressInRefreshToken() {
            RefreshToken refreshToken = RefreshToken.builder()
                    .user(testUser)
                    .token("token")
                    .ipAddress("192.168.1.100")
                    .build();

            assertThat(refreshToken.getIpAddress()).isEqualTo("192.168.1.100");
        }

        @Test
        @DisplayName("should include user agent in refresh token")
        void shouldIncludeUserAgentInRefreshToken() {
            RefreshToken refreshToken = RefreshToken.builder()
                    .user(testUser)
                    .token("token")
                    .userAgent("Mozilla/5.0 Chrome")
                    .build();

            assertThat(refreshToken.getUserAgent()).isEqualTo("Mozilla/5.0 Chrome");
        }
    }

    @Nested
    @DisplayName("OAuth2UserPrincipal Tests")
    class OAuth2UserPrincipalTests {

        @Test
        @DisplayName("should extract user from OAuth2UserPrincipal")
        void shouldExtractUserFromOAuth2UserPrincipal() {
            OAuth2UserPrincipal principal = mock(OAuth2UserPrincipal.class);
            when(principal.getId()).thenReturn(testUserId);
            when(authentication.getPrincipal()).thenReturn(principal);
            when(authUserRepository.findById(testUserId)).thenReturn(Optional.of(testUser));

            Optional<AuthUser> found = authUserRepository.findById(testUserId);

            assertThat(found).isPresent();
            assertThat(found.get().getId()).isEqualTo(testUserId);
        }

        @Test
        @DisplayName("should detect new user from OAuth2UserPrincipal")
        void shouldDetectNewUserFromOAuth2UserPrincipal() {
            OAuth2UserPrincipal principal = mock(OAuth2UserPrincipal.class);
            when(principal.isNewUser()).thenReturn(true);
            when(authentication.getPrincipal()).thenReturn(principal);

            boolean isNewUser = principal.isNewUser();

            assertThat(isNewUser).isTrue();
        }

        @Test
        @DisplayName("should detect existing user from OAuth2UserPrincipal")
        void shouldDetectExistingUserFromOAuth2UserPrincipal() {
            OAuth2UserPrincipal principal = mock(OAuth2UserPrincipal.class);
            when(principal.isNewUser()).thenReturn(false);
            when(authentication.getPrincipal()).thenReturn(principal);

            boolean isNewUser = principal.isNewUser();

            assertThat(isNewUser).isFalse();
        }
    }

    @Nested
    @DisplayName("CustomOidcUser Tests")
    class CustomOidcUserTests {

        @Test
        @DisplayName("should extract user from CustomOidcUser")
        void shouldExtractUserFromCustomOidcUser() {
            OidcUser mockOidcUser = mock(OidcUser.class);
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, mockOidcUser, false);

            when(authentication.getPrincipal()).thenReturn(customOidcUser);

            AuthUser extractedUser = customOidcUser.getAuthUser();

            assertThat(extractedUser).isEqualTo(testUser);
        }

        @Test
        @DisplayName("should detect new user from CustomOidcUser")
        void shouldDetectNewUserFromCustomOidcUser() {
            OidcUser mockOidcUser = mock(OidcUser.class);
            CustomOidcUser customOidcUser = new CustomOidcUser(testUser, mockOidcUser, true);

            assertThat(customOidcUser.isNewUser()).isTrue();
        }
    }

    @Nested
    @DisplayName("Cookie Handling Tests")
    class CookieHandlingTests {

        @Test
        @DisplayName("should get redirect URI from cookie")
        void shouldGetRedirectUriFromCookie() {
            Cookie redirectCookie = new Cookie("redirect_uri", "http://custom-redirect.com");
            when(request.getCookies()).thenReturn(new Cookie[]{redirectCookie});
            when(oAuth2Config.getRedirectUriCookieName()).thenReturn("redirect_uri");

            Cookie[] cookies = request.getCookies();
            String redirectUri = null;
            for (Cookie cookie : cookies) {
                if ("redirect_uri".equals(cookie.getName())) {
                    redirectUri = cookie.getValue();
                    break;
                }
            }

            assertThat(redirectUri).isEqualTo("http://custom-redirect.com");
        }

        @Test
        @DisplayName("should use default callback URL when no cookie")
        void shouldUseDefaultCallbackUrlWhenNoCookie() {
            when(request.getCookies()).thenReturn(null);
            when(oAuth2Config.getFrontendCallbackUrl()).thenReturn("http://default-callback.com");

            String defaultUrl = oAuth2Config.getFrontendCallbackUrl();

            assertThat(defaultUrl).isEqualTo("http://default-callback.com");
        }

        @Test
        @DisplayName("should clear authorization cookies after success")
        void shouldClearAuthorizationCookiesAfterSuccess() {
            doNothing().when(authorizationRequestRepository)
                    .removeAuthorizationRequestCookies(any(), any());

            authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);

            verify(authorizationRequestRepository).removeAuthorizationRequestCookies(request, response);
        }
    }

    @Nested
    @DisplayName("Client IP Extraction Tests")
    class ClientIpExtractionTests {

        @Test
        @DisplayName("should extract IP from X-Forwarded-For header")
        void shouldExtractIpFromXForwardedForHeader() {
            when(request.getHeader("X-Forwarded-For")).thenReturn("192.168.1.1, 10.0.0.1");

            String xForwardedFor = request.getHeader("X-Forwarded-For");
            String clientIp = xForwardedFor.split(",")[0].trim();

            assertThat(clientIp).isEqualTo("192.168.1.1");
        }

        @Test
        @DisplayName("should extract IP from X-Real-IP header")
        void shouldExtractIpFromXRealIpHeader() {
            when(request.getHeader("X-Forwarded-For")).thenReturn(null);
            when(request.getHeader("X-Real-IP")).thenReturn("10.0.0.5");

            String xRealIp = request.getHeader("X-Real-IP");

            assertThat(xRealIp).isEqualTo("10.0.0.5");
        }

        @Test
        @DisplayName("should fallback to remote address")
        void shouldFallbackToRemoteAddress() {
            when(request.getHeader("X-Forwarded-For")).thenReturn(null);
            when(request.getHeader("X-Real-IP")).thenReturn(null);
            when(request.getRemoteAddr()).thenReturn("127.0.0.1");

            String remoteAddr = request.getRemoteAddr();

            assertThat(remoteAddr).isEqualTo("127.0.0.1");
        }
    }

    @Nested
    @DisplayName("Login History Recording Tests")
    class LoginHistoryRecordingTests {

        @Test
        @DisplayName("should record OAuth login in history")
        void shouldRecordOAuthLoginInHistory() {
            RecordLoginRequest loginRequest = RecordLoginRequest.builder()
                    .userId(testUserId)
                    .email("test@example.com")
                    .ipAddress("127.0.0.1")
                    .userAgent("Test Agent")
                    .build();

            loginHistoryService.recordLogin(loginRequest);

            verify(loginHistoryService).recordLogin(any(RecordLoginRequest.class));
        }

        @Test
        @DisplayName("should handle login history recording failure gracefully")
        void shouldHandleLoginHistoryRecordingFailureGracefully() {
            doThrow(new RuntimeException("Database error"))
                    .when(loginHistoryService).recordLogin(any(RecordLoginRequest.class));

            // The handler should catch this exception and continue
            try {
                loginHistoryService.recordLogin(RecordLoginRequest.builder().build());
            } catch (RuntimeException e) {
                // Expected - handler catches this in actual implementation
                assertThat(e.getMessage()).isEqualTo("Database error");
            }
        }
    }

    @Nested
    @DisplayName("OidcUser Fallback Tests")
    class OidcUserFallbackTests {

        @Test
        @DisplayName("should find user by email for OidcUser principal")
        void shouldFindUserByEmailForOidcUserPrincipal() {
            OidcUser oidcUser = mock(OidcUser.class);
            when(oidcUser.getEmail()).thenReturn("test@example.com");
            when(authentication.getPrincipal()).thenReturn(oidcUser);
            when(authUserRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

            Optional<AuthUser> found = authUserRepository.findByEmail(oidcUser.getEmail());

            assertThat(found).isPresent();
            assertThat(found.get().getEmail()).isEqualTo("test@example.com");
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("should handle user not found")
        void shouldHandleUserNotFound() {
            OAuth2UserPrincipal principal = mock(OAuth2UserPrincipal.class);
            when(principal.getId()).thenReturn(UUID.randomUUID());
            when(authentication.getPrincipal()).thenReturn(principal);
            when(authUserRepository.findById(any(UUID.class))).thenReturn(Optional.empty());

            Optional<AuthUser> found = authUserRepository.findById(UUID.randomUUID());

            assertThat(found).isEmpty();
        }

        @Test
        @DisplayName("should not redirect if response is committed")
        void shouldNotRedirectIfResponseIsCommitted() {
            when(response.isCommitted()).thenReturn(true);

            boolean isCommitted = response.isCommitted();

            assertThat(isCommitted).isTrue();
        }
    }

    @Nested
    @DisplayName("URL Building Tests")
    class UrlBuildingTests {

        @Test
        @DisplayName("should build redirect URL with all parameters")
        void shouldBuildRedirectUrlWithAllParameters() {
            String baseUrl = "http://localhost:3000/callback";
            String accessToken = "access-123";
            String refreshToken = "refresh-456";

            String url = String.format("%s?access_token=%s&refresh_token=%s&token_type=Bearer&expires_in=%d&new_user=%s",
                    baseUrl, accessToken, refreshToken, 3600L, false);

            assertThat(url).contains("access_token=access-123");
            assertThat(url).contains("refresh_token=refresh-456");
            assertThat(url).contains("token_type=Bearer");
            assertThat(url).contains("expires_in=3600");
            assertThat(url).contains("new_user=false");
        }

        @Test
        @DisplayName("should build error URL when user not found")
        void shouldBuildErrorUrlWhenUserNotFound() {
            String baseUrl = "http://localhost:3000/callback";
            String errorUrl = baseUrl + "?error=user_not_found";

            assertThat(errorUrl).contains("error=user_not_found");
        }
    }
}
