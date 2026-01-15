package com.quckapp.auth.security.oauth2;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for OAuth2AuthenticationFailureHandler methods
 * Uses reflection and Spring Mock objects to avoid Mockito issues with Java 25
 */
@DisplayName("OAuth2AuthenticationFailureHandler Method Tests")
class OAuth2FailureHandlerMethodsTest {

    private OAuth2AuthenticationFailureHandler handler;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    // Stub OAuth2Config for testing
    static class TestOAuth2Config extends OAuth2Config {
        @Override
        public String getRedirectUriCookieName() {
            return "redirect_uri";
        }

        @Override
        public String getDefaultFailureUrl() {
            return "http://localhost:3000/login?error=true";
        }

        @Override
        public String getFrontendCallbackUrl() {
            return "http://localhost:3000/oauth/callback";
        }
    }

    @BeforeEach
    void setUp() {
        TestOAuth2Config config = new TestOAuth2Config();
        HttpCookieOAuth2AuthorizationRequestRepository authRepo =
            new HttpCookieOAuth2AuthorizationRequestRepository(config);

        handler = new OAuth2AuthenticationFailureHandler(config, authRepo);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Nested
    @DisplayName("getErrorCode() Tests via Reflection")
    class GetErrorCodeTests {

        @Test
        @DisplayName("should return email_not_found for email not found message")
        void shouldReturnEmailNotFoundCode() throws Exception {
            AuthenticationException exception = new AuthenticationException("email_not_found in OAuth response") {};

            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getErrorCode", AuthenticationException.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, exception);

            assertThat(result).isEqualTo("email_not_found");
        }

        @Test
        @DisplayName("should return processing_error for processing error message")
        void shouldReturnProcessingErrorCode() throws Exception {
            AuthenticationException exception = new AuthenticationException("processing_error occurred") {};

            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getErrorCode", AuthenticationException.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, exception);

            assertThat(result).isEqualTo("processing_error");
        }

        @Test
        @DisplayName("should return invalid_token for invalid token message")
        void shouldReturnInvalidTokenCode() throws Exception {
            AuthenticationException exception = new AuthenticationException("invalid_token received") {};

            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getErrorCode", AuthenticationException.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, exception);

            assertThat(result).isEqualTo("invalid_token");
        }

        @Test
        @DisplayName("should return authentication_failed for unknown error")
        void shouldReturnAuthenticationFailedForUnknownError() throws Exception {
            AuthenticationException exception = new AuthenticationException("Some unknown error") {};

            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getErrorCode", AuthenticationException.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, exception);

            assertThat(result).isEqualTo("authentication_failed");
        }

        @Test
        @DisplayName("should return authentication_failed for null message")
        void shouldReturnAuthenticationFailedForNullMessage() throws Exception {
            AuthenticationException exception = new AuthenticationException(null) {};

            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getErrorCode", AuthenticationException.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, exception);

            assertThat(result).isEqualTo("authentication_failed");
        }
    }

    @Nested
    @DisplayName("getCookieValue() Tests via Reflection")
    class GetCookieValueTests {

        @Test
        @DisplayName("should return empty when no cookies present")
        void shouldReturnEmptyWhenNoCookies() throws Exception {
            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getCookieValue", HttpServletRequest.class, String.class);
            method.setAccessible(true);

            @SuppressWarnings("unchecked")
            Optional<String> result = (Optional<String>) method.invoke(handler, request, "redirect_uri");

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should return cookie value when cookie exists")
        void shouldReturnCookieValueWhenExists() throws Exception {
            request.setCookies(new Cookie("redirect_uri", "http://custom.com/error"));

            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getCookieValue", HttpServletRequest.class, String.class);
            method.setAccessible(true);

            @SuppressWarnings("unchecked")
            Optional<String> result = (Optional<String>) method.invoke(handler, request, "redirect_uri");

            assertThat(result).isPresent();
            assertThat(result.get()).isEqualTo("http://custom.com/error");
        }

        @Test
        @DisplayName("should return empty when cookie name not found")
        void shouldReturnEmptyWhenCookieNameNotFound() throws Exception {
            request.setCookies(new Cookie("other_cookie", "value"));

            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getCookieValue", HttpServletRequest.class, String.class);
            method.setAccessible(true);

            @SuppressWarnings("unchecked")
            Optional<String> result = (Optional<String>) method.invoke(handler, request, "redirect_uri");

            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("should find correct cookie among multiple cookies")
        void shouldFindCorrectCookieAmongMultiple() throws Exception {
            request.setCookies(
                new Cookie("session_id", "abc123"),
                new Cookie("redirect_uri", "http://target.com/callback"),
                new Cookie("csrf_token", "xyz789")
            );

            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getCookieValue", HttpServletRequest.class, String.class);
            method.setAccessible(true);

            @SuppressWarnings("unchecked")
            Optional<String> result = (Optional<String>) method.invoke(handler, request, "redirect_uri");

            assertThat(result).isPresent();
            assertThat(result.get()).isEqualTo("http://target.com/callback");
        }
    }

    @Nested
    @DisplayName("getTargetUrl() Tests via Reflection")
    class GetTargetUrlTests {

        @Test
        @DisplayName("should build URL with error code and description")
        void shouldBuildUrlWithErrorCodeAndDescription() throws Exception {
            // Use message containing "email_not_found" since getErrorCode checks exception.getMessage()
            OAuth2Error error = new OAuth2Error("email_not_found", "email_not_found: Email was not provided", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getTargetUrl", HttpServletRequest.class, AuthenticationException.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, request, exception);

            assertThat(result).contains("error=email_not_found");
            assertThat(result).contains("error_description=");
        }

        @Test
        @DisplayName("should use default failure URL when no redirect cookie")
        void shouldUseDefaultFailureUrlWhenNoCookie() throws Exception {
            AuthenticationException exception = new AuthenticationException("Test error") {};

            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getTargetUrl", HttpServletRequest.class, AuthenticationException.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, request, exception);

            assertThat(result).startsWith("http://localhost:3000/login");
        }

        @Test
        @DisplayName("should use redirect URI from cookie when present")
        void shouldUseRedirectUriFromCookie() throws Exception {
            request.setCookies(new Cookie("redirect_uri", "http://custom.com/oauth-error"));
            AuthenticationException exception = new AuthenticationException("Test error") {};

            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getTargetUrl", HttpServletRequest.class, AuthenticationException.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, request, exception);

            assertThat(result).startsWith("http://custom.com/oauth-error");
        }

        @Test
        @DisplayName("should URL encode error description")
        void shouldUrlEncodeErrorDescription() throws Exception {
            OAuth2Error error = new OAuth2Error("error", "Error with spaces & special chars!", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            Method method = OAuth2AuthenticationFailureHandler.class
                    .getDeclaredMethod("getTargetUrl", HttpServletRequest.class, AuthenticationException.class);
            method.setAccessible(true);

            String result = (String) method.invoke(handler, request, exception);

            assertThat(result).doesNotContain(" ");
            assertThat(result).contains("error_description=");
        }
    }

    @Nested
    @DisplayName("onAuthenticationFailure() Integration Tests")
    class OnAuthenticationFailureTests {

        @Test
        @DisplayName("should redirect to failure URL")
        void shouldRedirectToFailureUrl() throws IOException {
            OAuth2Error error = new OAuth2Error("access_denied", "User denied access", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            handler.onAuthenticationFailure(request, response, exception);

            assertThat(response.getRedirectedUrl()).isNotNull();
            assertThat(response.getRedirectedUrl()).contains("error=");
        }

        @Test
        @DisplayName("should include error code in redirect URL")
        void shouldIncludeErrorCodeInRedirectUrl() throws IOException {
            OAuth2Error error = new OAuth2Error("invalid_grant", "Invalid grant", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            handler.onAuthenticationFailure(request, response, exception);

            assertThat(response.getRedirectedUrl()).contains("error=authentication_failed");
        }

        @Test
        @DisplayName("should include error description in redirect URL")
        void shouldIncludeErrorDescriptionInRedirectUrl() throws IOException {
            OAuth2Error error = new OAuth2Error("error", "Test error message", null);
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

            handler.onAuthenticationFailure(request, response, exception);

            assertThat(response.getRedirectedUrl()).contains("error_description=");
        }

        @Test
        @DisplayName("should handle email_not_found error")
        void shouldHandleEmailNotFoundError() throws IOException {
            AuthenticationException exception = new AuthenticationException("email_not_found: No email provided") {};

            handler.onAuthenticationFailure(request, response, exception);

            assertThat(response.getRedirectedUrl()).contains("error=email_not_found");
        }

        @Test
        @DisplayName("should handle processing_error")
        void shouldHandleProcessingError() throws IOException {
            AuthenticationException exception = new AuthenticationException("processing_error during OAuth") {};

            handler.onAuthenticationFailure(request, response, exception);

            assertThat(response.getRedirectedUrl()).contains("error=processing_error");
        }

        @Test
        @DisplayName("should handle invalid_token error")
        void shouldHandleInvalidTokenError() throws IOException {
            AuthenticationException exception = new AuthenticationException("invalid_token received from provider") {};

            handler.onAuthenticationFailure(request, response, exception);

            assertThat(response.getRedirectedUrl()).contains("error=invalid_token");
        }

        @Test
        @DisplayName("should use custom redirect URI from cookie")
        void shouldUseCustomRedirectUriFromCookie() throws IOException {
            request.setCookies(new Cookie("redirect_uri", "http://myapp.com/oauth-failed"));
            AuthenticationException exception = new AuthenticationException("Some error") {};

            handler.onAuthenticationFailure(request, response, exception);

            assertThat(response.getRedirectedUrl()).startsWith("http://myapp.com/oauth-failed");
        }
    }
}
