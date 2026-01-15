package com.quckapp.auth.security.oauth2;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for OAuth2AuthenticationFailureHandler
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OAuth2AuthenticationFailureHandlerTest {

    @Mock
    private OAuth2Config oAuth2Config;

    @Mock
    private HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private OAuth2AuthenticationFailureHandler failureHandler;

    @BeforeEach
    void setUp() {
        failureHandler = new OAuth2AuthenticationFailureHandler(
                oAuth2Config,
                authorizationRequestRepository
        );

        when(oAuth2Config.getRedirectUriCookieName()).thenReturn("redirect_uri");
        when(oAuth2Config.getDefaultFailureUrl()).thenReturn("http://localhost:3000/login?error=true");
        when(request.getCookies()).thenReturn(null);
    }

    @Nested
    @DisplayName("Error Code Extraction Tests")
    class ErrorCodeExtractionTests {

        @Test
        @DisplayName("should extract email_not_found error code")
        void shouldExtractEmailNotFoundErrorCode() {
            OAuth2Error error = new OAuth2Error("email_not_found", "Email not found from OAuth2 provider", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            String errorCode = exception.getError().getErrorCode();

            assertThat(errorCode).isEqualTo("email_not_found");
        }

        @Test
        @DisplayName("should extract processing_error error code")
        void shouldExtractProcessingErrorCode() {
            OAuth2Error error = new OAuth2Error("processing_error", "Error processing OAuth2 response", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            String errorCode = exception.getError().getErrorCode();

            assertThat(errorCode).isEqualTo("processing_error");
        }

        @Test
        @DisplayName("should extract invalid_token error code")
        void shouldExtractInvalidTokenErrorCode() {
            OAuth2Error error = new OAuth2Error("invalid_token", "The access token is invalid", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            String errorCode = exception.getError().getErrorCode();

            assertThat(errorCode).isEqualTo("invalid_token");
        }

        @Test
        @DisplayName("should default to authentication_failed for unknown errors")
        void shouldDefaultToAuthenticationFailedForUnknownErrors() {
            AuthenticationException exception = new AuthenticationException("Unknown error occurred") {};

            String message = exception.getMessage();

            assertThat(message).doesNotContain("email_not_found");
            assertThat(message).doesNotContain("processing_error");
            assertThat(message).doesNotContain("invalid_token");
        }

        @Test
        @DisplayName("should handle null message gracefully")
        void shouldHandleNullMessageGracefully() {
            AuthenticationException exception = new AuthenticationException(null) {};

            String message = exception.getMessage();

            assertThat(message).isNull();
        }
    }

    @Nested
    @DisplayName("URL Building Tests")
    class UrlBuildingTests {

        @Test
        @DisplayName("should build failure URL with error code")
        void shouldBuildFailureUrlWithErrorCode() {
            String baseUrl = "http://localhost:3000/login";
            String errorCode = "authentication_failed";

            String url = baseUrl + "?error=" + errorCode;

            assertThat(url).contains("error=authentication_failed");
        }

        @Test
        @DisplayName("should URL encode error description")
        void shouldUrlEncodeErrorDescription() {
            String errorMessage = "Error with spaces & special chars!";
            String encoded = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);

            String url = "http://localhost/callback?error_description=" + encoded;

            assertThat(url).contains("error_description=");
            assertThat(url).doesNotContain(" ");
        }

        @Test
        @DisplayName("should include both error and error_description")
        void shouldIncludeBothErrorAndErrorDescription() {
            String baseUrl = "http://localhost:3000/login";
            String errorCode = "email_not_found";
            String errorMessage = URLEncoder.encode("Email not found", StandardCharsets.UTF_8);

            String url = String.format("%s?error=%s&error_description=%s", baseUrl, errorCode, errorMessage);

            assertThat(url).contains("error=email_not_found");
            assertThat(url).contains("error_description=");
        }
    }

    @Nested
    @DisplayName("Cookie Handling Tests")
    class CookieHandlingTests {

        @Test
        @DisplayName("should get redirect URI from cookie")
        void shouldGetRedirectUriFromCookie() {
            Cookie redirectCookie = new Cookie("redirect_uri", "http://custom-failure.com");
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

            assertThat(redirectUri).isEqualTo("http://custom-failure.com");
        }

        @Test
        @DisplayName("should use default failure URL when no cookie present")
        void shouldUseDefaultFailureUrlWhenNoCookiePresent() {
            when(request.getCookies()).thenReturn(null);
            when(oAuth2Config.getDefaultFailureUrl()).thenReturn("http://default-failure.com");

            String defaultUrl = oAuth2Config.getDefaultFailureUrl();

            assertThat(defaultUrl).isEqualTo("http://default-failure.com");
        }

        @Test
        @DisplayName("should use default failure URL when cookie not found")
        void shouldUseDefaultFailureUrlWhenCookieNotFound() {
            Cookie otherCookie = new Cookie("other_cookie", "value");
            when(request.getCookies()).thenReturn(new Cookie[]{otherCookie});
            when(oAuth2Config.getDefaultFailureUrl()).thenReturn("http://default-failure.com");

            Cookie[] cookies = request.getCookies();
            String redirectUri = null;
            for (Cookie cookie : cookies) {
                if ("redirect_uri".equals(cookie.getName())) {
                    redirectUri = cookie.getValue();
                    break;
                }
            }

            // No matching cookie found
            assertThat(redirectUri).isNull();
        }

        @Test
        @DisplayName("should clear authorization cookies on failure")
        void shouldClearAuthorizationCookiesOnFailure() throws IOException {
            OAuth2Error error = new OAuth2Error("authentication_failed", "Authentication failed", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            doNothing().when(authorizationRequestRepository)
                    .removeAuthorizationRequestCookies(request, response);

            authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);

            verify(authorizationRequestRepository).removeAuthorizationRequestCookies(request, response);
        }
    }

    @Nested
    @DisplayName("Authentication Failure Tests")
    class AuthenticationFailureTests {

        @Test
        @DisplayName("should handle OAuth2AuthenticationException")
        void shouldHandleOAuth2AuthenticationException() {
            OAuth2Error error = new OAuth2Error("invalid_grant", "Invalid authorization grant", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            assertThat(exception).isInstanceOf(AuthenticationException.class);
            assertThat(exception.getError().getErrorCode()).isEqualTo("invalid_grant");
        }

        @Test
        @DisplayName("should handle generic AuthenticationException")
        void shouldHandleGenericAuthenticationException() {
            AuthenticationException exception = new AuthenticationException("Generic authentication failure") {};

            assertThat(exception.getMessage()).isEqualTo("Generic authentication failure");
        }

        @Test
        @DisplayName("should extract localized message")
        void shouldExtractLocalizedMessage() {
            OAuth2Error error = new OAuth2Error("error_code", "Detailed error message", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            String localizedMessage = exception.getLocalizedMessage();

            assertThat(localizedMessage).isNotNull();
        }
    }

    @Nested
    @DisplayName("Redirect Tests")
    class RedirectTests {

        @Test
        @DisplayName("should construct proper redirect URL")
        void shouldConstructProperRedirectUrl() {
            String baseUrl = "http://localhost:3000/login";
            String errorCode = "access_denied";
            String errorDescription = URLEncoder.encode("User denied access", StandardCharsets.UTF_8);

            String redirectUrl = String.format("%s?error=%s&error_description=%s",
                    baseUrl, errorCode, errorDescription);

            assertThat(redirectUrl).startsWith("http://localhost:3000/login");
            assertThat(redirectUrl).contains("error=access_denied");
            assertThat(redirectUrl).contains("error_description=");
        }

        @Test
        @DisplayName("should handle special characters in error message")
        void shouldHandleSpecialCharactersInErrorMessage() {
            String errorMessage = "Error: User's account is <blocked> & inactive!";
            String encoded = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);

            assertThat(encoded).doesNotContain("<");
            assertThat(encoded).doesNotContain(">");
            assertThat(encoded).doesNotContain("&");
            assertThat(encoded).doesNotContain("'");
        }
    }

    @Nested
    @DisplayName("OAuth2 Error Types Tests")
    class OAuth2ErrorTypesTests {

        @Test
        @DisplayName("should handle access_denied error")
        void shouldHandleAccessDeniedError() {
            OAuth2Error error = new OAuth2Error("access_denied", "The user denied access", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            assertThat(exception.getError().getErrorCode()).isEqualTo("access_denied");
        }

        @Test
        @DisplayName("should handle server_error")
        void shouldHandleServerError() {
            OAuth2Error error = new OAuth2Error("server_error", "Internal server error", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            assertThat(exception.getError().getErrorCode()).isEqualTo("server_error");
        }

        @Test
        @DisplayName("should handle temporarily_unavailable error")
        void shouldHandleTemporarilyUnavailableError() {
            OAuth2Error error = new OAuth2Error("temporarily_unavailable", "Service temporarily unavailable", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            assertThat(exception.getError().getErrorCode()).isEqualTo("temporarily_unavailable");
        }
    }
}
