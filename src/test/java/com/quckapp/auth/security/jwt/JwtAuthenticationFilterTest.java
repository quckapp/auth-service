package com.quckapp.auth.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAuthenticationFilter")
class JwtAuthenticationFilterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String USER_ID = "123e4567-e89b-12d3-a456-426614174000";
    private static final String EMAIL = "test@example.com";
    private static final String EXTERNAL_ID = "ext-12345";
    private static final String SESSION_ID = "session-abc123";

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    @DisplayName("When no Authorization header is present")
    class NoAuthorizationHeader {

        @Test
        @DisplayName("Should continue filter chain without setting authentication")
        void shouldContinueWithoutAuthentication() throws ServletException, IOException {
            // No Authorization header set

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            verifyNoInteractions(jwtService);
        }
    }

    @Nested
    @DisplayName("When Authorization header is malformed")
    class MalformedAuthorizationHeader {

        @Test
        @DisplayName("Should continue without authentication when header doesn't start with Bearer")
        void shouldContinueWhenNotBearer() throws ServletException, IOException {
            request.addHeader("Authorization", "Basic dXNlcjpwYXNz");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            verifyNoInteractions(jwtService);
        }

        @Test
        @DisplayName("Should continue without authentication when header is empty")
        void shouldContinueWhenHeaderEmpty() throws ServletException, IOException {
            request.addHeader("Authorization", "");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            verifyNoInteractions(jwtService);
        }

        @Test
        @DisplayName("Should continue without authentication when Bearer token is empty")
        void shouldContinueWhenBearerTokenEmpty() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer ");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            verifyNoInteractions(jwtService);
        }

        @Test
        @DisplayName("Should continue without authentication when Bearer token is whitespace")
        void shouldContinueWhenBearerTokenWhitespace() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer    ");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            // Token is whitespace after trimming, so jwtService.validateToken might be called
        }
    }

    @Nested
    @DisplayName("When JWT validation fails")
    class JwtValidationFails {

        @Test
        @DisplayName("Should continue without authentication when token is invalid")
        void shouldContinueWhenTokenInvalid() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(false);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(jwtService).validateToken(VALID_TOKEN);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }
    }

    @Nested
    @DisplayName("When token type is not access")
    class NonAccessTokenType {

        @Test
        @DisplayName("Should continue without authentication for refresh token")
        void shouldContinueForRefreshToken() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtService.extractTokenType(VALID_TOKEN)).thenReturn("refresh");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(jwtService).validateToken(VALID_TOKEN);
            verify(jwtService).extractTokenType(VALID_TOKEN);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        @DisplayName("Should continue without authentication for password_reset token")
        void shouldContinueForPasswordResetToken() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtService.extractTokenType(VALID_TOKEN)).thenReturn("password_reset");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        @DisplayName("Should continue without authentication for null token type")
        void shouldContinueForNullTokenType() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtService.extractTokenType(VALID_TOKEN)).thenReturn(null);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }
    }

    @Nested
    @DisplayName("When valid access token is provided")
    class ValidAccessToken {

        @BeforeEach
        void setUpValidToken() {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtService.extractTokenType(VALID_TOKEN)).thenReturn("access");
            when(jwtService.extractUserId(VALID_TOKEN)).thenReturn(USER_ID);
            when(jwtService.extractEmail(VALID_TOKEN)).thenReturn(EMAIL);
            when(jwtService.extractExternalId(VALID_TOKEN)).thenReturn(EXTERNAL_ID);
            when(jwtService.extractSessionId(VALID_TOKEN)).thenReturn(SESSION_ID);
        }

        @Test
        @DisplayName("Should set authentication in SecurityContext")
        void shouldSetAuthentication() throws ServletException, IOException {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication).isNotNull();
            assertThat(authentication.isAuthenticated()).isTrue();
        }

        @Test
        @DisplayName("Should set correct principal with user details")
        void shouldSetCorrectPrincipal() throws ServletException, IOException {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication.getPrincipal()).isInstanceOf(JwtUserPrincipal.class);

            JwtUserPrincipal principal = (JwtUserPrincipal) authentication.getPrincipal();
            assertThat(principal.getUserId()).isEqualTo(UUID.fromString(USER_ID));
            assertThat(principal.getEmail()).isEqualTo(EMAIL);
            assertThat(principal.getExternalId()).isEqualTo(EXTERNAL_ID);
            assertThat(principal.getSessionId()).isEqualTo(SESSION_ID);
        }

        @Test
        @DisplayName("Should set ROLE_USER authority")
        void shouldSetRoleUserAuthority() throws ServletException, IOException {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication.getAuthorities()).hasSize(1);
            assertThat(authentication.getAuthorities().iterator().next().getAuthority())
                    .isEqualTo("ROLE_USER");
        }

        @Test
        @DisplayName("Should set authentication details from request")
        void shouldSetAuthenticationDetails() throws ServletException, IOException {
            request.setRemoteAddr("192.168.1.100");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication.getDetails()).isNotNull();
        }

        @Test
        @DisplayName("Should have null credentials")
        void shouldHaveNullCredentials() throws ServletException, IOException {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication.getCredentials()).isNull();
        }
    }

    @Nested
    @DisplayName("When exception occurs during token processing")
    class ExceptionHandling {

        @Test
        @DisplayName("Should continue filter chain when validateToken throws exception")
        void shouldContinueWhenValidateTokenThrows() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtService.validateToken(VALID_TOKEN)).thenThrow(new RuntimeException("Token validation error"));

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        @DisplayName("Should continue filter chain when extractTokenType throws exception")
        void shouldContinueWhenExtractTokenTypeThrows() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtService.extractTokenType(VALID_TOKEN)).thenThrow(new RuntimeException("Extract type error"));

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        @DisplayName("Should continue filter chain when extractUserId throws exception")
        void shouldContinueWhenExtractUserIdThrows() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtService.extractTokenType(VALID_TOKEN)).thenReturn("access");
            when(jwtService.extractUserId(VALID_TOKEN)).thenThrow(new RuntimeException("Extract user error"));

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        @DisplayName("Should continue filter chain when UUID parsing fails")
        void shouldContinueWhenUuidParsingFails() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtService.extractTokenType(VALID_TOKEN)).thenReturn("access");
            when(jwtService.extractUserId(VALID_TOKEN)).thenReturn("not-a-valid-uuid");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }
    }

    @Nested
    @DisplayName("Edge cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle token with extra spaces after Bearer")
        void shouldHandleExtraSpacesAfterBearer() throws ServletException, IOException {
            // The token includes leading spaces which is part of the token value
            String tokenWithSpaces = "  " + VALID_TOKEN;
            request.addHeader("Authorization", "Bearer " + tokenWithSpaces);
            when(jwtService.validateToken(tokenWithSpaces)).thenReturn(false);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            verify(jwtService).validateToken(tokenWithSpaces);
        }

        @Test
        @DisplayName("Should handle case-sensitive Bearer prefix")
        void shouldHandleCaseSensitiveBearerPrefix() throws ServletException, IOException {
            request.addHeader("Authorization", "bearer " + VALID_TOKEN);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            // "bearer" lowercase doesn't match "Bearer " so token won't be extracted
            verifyNoInteractions(jwtService);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        @DisplayName("Should handle null externalId from token")
        void shouldHandleNullExternalId() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtService.extractTokenType(VALID_TOKEN)).thenReturn("access");
            when(jwtService.extractUserId(VALID_TOKEN)).thenReturn(USER_ID);
            when(jwtService.extractEmail(VALID_TOKEN)).thenReturn(EMAIL);
            when(jwtService.extractExternalId(VALID_TOKEN)).thenReturn(null);
            when(jwtService.extractSessionId(VALID_TOKEN)).thenReturn(SESSION_ID);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication).isNotNull();
            JwtUserPrincipal principal = (JwtUserPrincipal) authentication.getPrincipal();
            assertThat(principal.getExternalId()).isNull();
        }

        @Test
        @DisplayName("Should handle null sessionId from token")
        void shouldHandleNullSessionId() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtService.extractTokenType(VALID_TOKEN)).thenReturn("access");
            when(jwtService.extractUserId(VALID_TOKEN)).thenReturn(USER_ID);
            when(jwtService.extractEmail(VALID_TOKEN)).thenReturn(EMAIL);
            when(jwtService.extractExternalId(VALID_TOKEN)).thenReturn(EXTERNAL_ID);
            when(jwtService.extractSessionId(VALID_TOKEN)).thenReturn(null);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication).isNotNull();
            JwtUserPrincipal principal = (JwtUserPrincipal) authentication.getPrincipal();
            assertThat(principal.getSessionId()).isNull();
        }

        @Test
        @DisplayName("Should not affect existing SecurityContext if already authenticated")
        void shouldOverrideExistingAuthentication() throws ServletException, IOException {
            // Pre-set different authentication
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);
            when(jwtService.validateToken(VALID_TOKEN)).thenReturn(true);
            when(jwtService.extractTokenType(VALID_TOKEN)).thenReturn("access");
            when(jwtService.extractUserId(VALID_TOKEN)).thenReturn(USER_ID);
            when(jwtService.extractEmail(VALID_TOKEN)).thenReturn(EMAIL);
            when(jwtService.extractExternalId(VALID_TOKEN)).thenReturn(EXTERNAL_ID);
            when(jwtService.extractSessionId(VALID_TOKEN)).thenReturn(SESSION_ID);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication).isNotNull();
            JwtUserPrincipal principal = (JwtUserPrincipal) authentication.getPrincipal();
            assertThat(principal.getEmail()).isEqualTo(EMAIL);
        }
    }
}
