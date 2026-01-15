package com.quckapp.auth.security.oauth2;

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
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.SerializationUtils;

import java.util.Base64;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for HttpCookieOAuth2AuthorizationRequestRepository
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class HttpCookieOAuth2AuthorizationRequestRepositoryTest {

    private static final String AUTH_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    private static final String REDIRECT_URI_COOKIE_NAME = "redirect_uri";

    @Mock
    private OAuth2Config oAuth2Config;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private HttpCookieOAuth2AuthorizationRequestRepository repository;

    @BeforeEach
    void setUp() {
        repository = new HttpCookieOAuth2AuthorizationRequestRepository(oAuth2Config);

        when(oAuth2Config.getRedirectUriCookieName()).thenReturn(REDIRECT_URI_COOKIE_NAME);
        when(oAuth2Config.getCookieExpireSeconds()).thenReturn(180);
        when(request.getCookies()).thenReturn(null);
    }

    private OAuth2AuthorizationRequest createAuthorizationRequest() {
        return OAuth2AuthorizationRequest.authorizationCode()
                .clientId("test-client")
                .authorizationUri("https://provider.com/oauth/authorize")
                .redirectUri("http://localhost/callback")
                .state("test-state-123")
                .build();
    }

    private String serializeRequest(OAuth2AuthorizationRequest request) {
        return Base64.getUrlEncoder().encodeToString(SerializationUtils.serialize(request));
    }

    @Nested
    @DisplayName("Load Authorization Request Tests")
    class LoadAuthorizationRequestTests {

        @Test
        @DisplayName("should load authorization request from cookie")
        void shouldLoadAuthorizationRequestFromCookie() {
            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();
            String serialized = serializeRequest(authRequest);
            Cookie authCookie = new Cookie(AUTH_REQUEST_COOKIE_NAME, serialized);

            when(request.getCookies()).thenReturn(new Cookie[]{authCookie});

            OAuth2AuthorizationRequest loaded = repository.loadAuthorizationRequest(request);

            assertThat(loaded).isNotNull();
            assertThat(loaded.getClientId()).isEqualTo("test-client");
            assertThat(loaded.getState()).isEqualTo("test-state-123");
        }

        @Test
        @DisplayName("should return null when no cookie present")
        void shouldReturnNullWhenNoCookiePresent() {
            when(request.getCookies()).thenReturn(null);

            OAuth2AuthorizationRequest loaded = repository.loadAuthorizationRequest(request);

            assertThat(loaded).isNull();
        }

        @Test
        @DisplayName("should return null when cookie not found")
        void shouldReturnNullWhenCookieNotFound() {
            Cookie otherCookie = new Cookie("other_cookie", "value");
            when(request.getCookies()).thenReturn(new Cookie[]{otherCookie});

            OAuth2AuthorizationRequest loaded = repository.loadAuthorizationRequest(request);

            assertThat(loaded).isNull();
        }

        @Test
        @DisplayName("should find cookie among multiple cookies")
        void shouldFindCookieAmongMultipleCookies() {
            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();
            String serialized = serializeRequest(authRequest);

            Cookie cookie1 = new Cookie("session", "abc123");
            Cookie authCookie = new Cookie(AUTH_REQUEST_COOKIE_NAME, serialized);
            Cookie cookie3 = new Cookie("preferences", "dark");

            when(request.getCookies()).thenReturn(new Cookie[]{cookie1, authCookie, cookie3});

            OAuth2AuthorizationRequest loaded = repository.loadAuthorizationRequest(request);

            assertThat(loaded).isNotNull();
            assertThat(loaded.getState()).isEqualTo("test-state-123");
        }
    }

    @Nested
    @DisplayName("Save Authorization Request Tests")
    class SaveAuthorizationRequestTests {

        @Test
        @DisplayName("should save authorization request to cookie")
        void shouldSaveAuthorizationRequestToCookie() {
            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();
            ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

            doNothing().when(response).addCookie(cookieCaptor.capture());

            repository.saveAuthorizationRequest(authRequest, request, response);

            Cookie savedCookie = cookieCaptor.getAllValues().stream()
                    .filter(c -> AUTH_REQUEST_COOKIE_NAME.equals(c.getName()))
                    .findFirst()
                    .orElse(null);

            assertThat(savedCookie).isNotNull();
            assertThat(savedCookie.isHttpOnly()).isTrue();
            assertThat(savedCookie.getSecure()).isTrue();
            assertThat(savedCookie.getMaxAge()).isEqualTo(180);
        }

        @Test
        @DisplayName("should delete cookies when request is null")
        void shouldDeleteCookiesWhenRequestIsNull() {
            Cookie authCookie = new Cookie(AUTH_REQUEST_COOKIE_NAME, "value");
            Cookie redirectCookie = new Cookie(REDIRECT_URI_COOKIE_NAME, "http://redirect.com");

            when(request.getCookies()).thenReturn(new Cookie[]{authCookie, redirectCookie});

            repository.saveAuthorizationRequest(null, request, response);

            verify(response, atLeast(0)).addCookie(any(Cookie.class));
        }

        @Test
        @DisplayName("should save redirect URI cookie when provided")
        void shouldSaveRedirectUriCookieWhenProvided() {
            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();
            ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

            when(request.getParameter("redirect_uri")).thenReturn("http://custom-redirect.com");
            doNothing().when(response).addCookie(cookieCaptor.capture());

            repository.saveAuthorizationRequest(authRequest, request, response);

            boolean hasRedirectCookie = cookieCaptor.getAllValues().stream()
                    .anyMatch(c -> REDIRECT_URI_COOKIE_NAME.equals(c.getName()));

            assertThat(hasRedirectCookie).isTrue();
        }

        @Test
        @DisplayName("should not save redirect URI cookie when not provided")
        void shouldNotSaveRedirectUriCookieWhenNotProvided() {
            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();
            ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

            when(request.getParameter("redirect_uri")).thenReturn(null);
            doNothing().when(response).addCookie(cookieCaptor.capture());

            repository.saveAuthorizationRequest(authRequest, request, response);

            boolean hasRedirectCookie = cookieCaptor.getAllValues().stream()
                    .anyMatch(c -> REDIRECT_URI_COOKIE_NAME.equals(c.getName()) && !c.getValue().isEmpty());

            // Cookie should not be added for redirect_uri
        }

        @Test
        @DisplayName("should not save redirect URI cookie when empty string")
        void shouldNotSaveRedirectUriCookieWhenEmptyString() {
            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();

            when(request.getParameter("redirect_uri")).thenReturn("");

            repository.saveAuthorizationRequest(authRequest, request, response);

            // Only auth request cookie should be added
        }
    }

    @Nested
    @DisplayName("Remove Authorization Request Tests")
    class RemoveAuthorizationRequestTests {

        @Test
        @DisplayName("should remove and return authorization request")
        void shouldRemoveAndReturnAuthorizationRequest() {
            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();
            String serialized = serializeRequest(authRequest);
            Cookie authCookie = new Cookie(AUTH_REQUEST_COOKIE_NAME, serialized);

            when(request.getCookies()).thenReturn(new Cookie[]{authCookie});

            OAuth2AuthorizationRequest removed = repository.removeAuthorizationRequest(request, response);

            assertThat(removed).isNotNull();
            assertThat(removed.getClientId()).isEqualTo("test-client");
            verify(response, atLeastOnce()).addCookie(any(Cookie.class));
        }

        @Test
        @DisplayName("should return null when no request to remove")
        void shouldReturnNullWhenNoRequestToRemove() {
            when(request.getCookies()).thenReturn(null);

            OAuth2AuthorizationRequest removed = repository.removeAuthorizationRequest(request, response);

            assertThat(removed).isNull();
        }

        @Test
        @DisplayName("should delete cookie when removing request")
        void shouldDeleteCookieWhenRemovingRequest() {
            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();
            String serialized = serializeRequest(authRequest);
            Cookie authCookie = new Cookie(AUTH_REQUEST_COOKIE_NAME, serialized);
            ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

            when(request.getCookies()).thenReturn(new Cookie[]{authCookie});
            doNothing().when(response).addCookie(cookieCaptor.capture());

            repository.removeAuthorizationRequest(request, response);

            Cookie deletedCookie = cookieCaptor.getValue();
            assertThat(deletedCookie.getName()).isEqualTo(AUTH_REQUEST_COOKIE_NAME);
            assertThat(deletedCookie.getMaxAge()).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("Remove Authorization Request Cookies Tests")
    class RemoveAuthorizationRequestCookiesTests {

        @Test
        @DisplayName("should remove all authorization cookies")
        void shouldRemoveAllAuthorizationCookies() {
            Cookie authCookie = new Cookie(AUTH_REQUEST_COOKIE_NAME, "auth-value");
            Cookie redirectCookie = new Cookie(REDIRECT_URI_COOKIE_NAME, "redirect-value");
            ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

            when(request.getCookies()).thenReturn(new Cookie[]{authCookie, redirectCookie});
            doNothing().when(response).addCookie(cookieCaptor.capture());

            repository.removeAuthorizationRequestCookies(request, response);

            // Verify both cookies are deleted
            assertThat(cookieCaptor.getAllValues()).hasSize(2);
            assertThat(cookieCaptor.getAllValues()).allMatch(c -> c.getMaxAge() == 0);
        }

        @Test
        @DisplayName("should handle empty cookies array")
        void shouldHandleEmptyCookiesArray() {
            when(request.getCookies()).thenReturn(new Cookie[]{});

            // Should not throw any exception
            repository.removeAuthorizationRequestCookies(request, response);

            // Verify no cookies were deleted (none to delete)
            verify(response, never()).addCookie(any(Cookie.class));
        }

        @Test
        @DisplayName("should handle null cookies")
        void shouldHandleNullCookies() {
            when(request.getCookies()).thenReturn(null);

            // Should not throw any exception
            repository.removeAuthorizationRequestCookies(request, response);

            // Verify no cookies were deleted (none to delete)
            verify(response, never()).addCookie(any(Cookie.class));
        }
    }

    @Nested
    @DisplayName("Cookie Configuration Tests")
    class CookieConfigurationTests {

        @Test
        @DisplayName("should set cookie path to root")
        void shouldSetCookiePathToRoot() {
            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();
            ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

            doNothing().when(response).addCookie(cookieCaptor.capture());

            repository.saveAuthorizationRequest(authRequest, request, response);

            Cookie savedCookie = cookieCaptor.getAllValues().stream()
                    .filter(c -> AUTH_REQUEST_COOKIE_NAME.equals(c.getName()))
                    .findFirst()
                    .orElse(null);

            assertThat(savedCookie).isNotNull();
            assertThat(savedCookie.getPath()).isEqualTo("/");
        }

        @Test
        @DisplayName("should set cookie as HTTP only")
        void shouldSetCookieAsHttpOnly() {
            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();
            ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

            doNothing().when(response).addCookie(cookieCaptor.capture());

            repository.saveAuthorizationRequest(authRequest, request, response);

            Cookie savedCookie = cookieCaptor.getAllValues().stream()
                    .filter(c -> AUTH_REQUEST_COOKIE_NAME.equals(c.getName()))
                    .findFirst()
                    .orElse(null);

            assertThat(savedCookie).isNotNull();
            assertThat(savedCookie.isHttpOnly()).isTrue();
        }

        @Test
        @DisplayName("should set cookie as secure")
        void shouldSetCookieAsSecure() {
            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();
            ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

            doNothing().when(response).addCookie(cookieCaptor.capture());

            repository.saveAuthorizationRequest(authRequest, request, response);

            Cookie savedCookie = cookieCaptor.getAllValues().stream()
                    .filter(c -> AUTH_REQUEST_COOKIE_NAME.equals(c.getName()))
                    .findFirst()
                    .orElse(null);

            assertThat(savedCookie).isNotNull();
            assertThat(savedCookie.getSecure()).isTrue();
        }

        @Test
        @DisplayName("should use configured expiration time")
        void shouldUseConfiguredExpirationTime() {
            when(oAuth2Config.getCookieExpireSeconds()).thenReturn(300);

            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();
            ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

            doNothing().when(response).addCookie(cookieCaptor.capture());

            repository.saveAuthorizationRequest(authRequest, request, response);

            Cookie savedCookie = cookieCaptor.getAllValues().stream()
                    .filter(c -> AUTH_REQUEST_COOKIE_NAME.equals(c.getName()))
                    .findFirst()
                    .orElse(null);

            assertThat(savedCookie).isNotNull();
            assertThat(savedCookie.getMaxAge()).isEqualTo(300);
        }
    }

    @Nested
    @DisplayName("Serialization Tests")
    class SerializationTests {

        @Test
        @DisplayName("should serialize and deserialize authorization request")
        void shouldSerializeAndDeserializeAuthorizationRequest() {
            OAuth2AuthorizationRequest original = createAuthorizationRequest();
            String serialized = serializeRequest(original);

            OAuth2AuthorizationRequest deserialized = (OAuth2AuthorizationRequest)
                    SerializationUtils.deserialize(Base64.getUrlDecoder().decode(serialized));

            assertThat(deserialized.getClientId()).isEqualTo(original.getClientId());
            assertThat(deserialized.getState()).isEqualTo(original.getState());
            assertThat(deserialized.getAuthorizationUri()).isEqualTo(original.getAuthorizationUri());
        }

        @Test
        @DisplayName("should use URL-safe Base64 encoding")
        void shouldUseUrlSafeBase64Encoding() {
            OAuth2AuthorizationRequest authRequest = createAuthorizationRequest();
            String serialized = serializeRequest(authRequest);

            // URL-safe Base64 should not contain + or /
            assertThat(serialized).doesNotContain("+");
            assertThat(serialized).doesNotContain("/");
        }

        @Test
        @DisplayName("should preserve all authorization request fields")
        void shouldPreserveAllAuthorizationRequestFields() {
            OAuth2AuthorizationRequest original = OAuth2AuthorizationRequest.authorizationCode()
                    .clientId("client-123")
                    .authorizationUri("https://auth.provider.com/authorize")
                    .redirectUri("http://app.example.com/oauth/callback")
                    .state("unique-state-value")
                    .scope("openid", "profile", "email")
                    .build();

            String serialized = serializeRequest(original);
            OAuth2AuthorizationRequest deserialized = (OAuth2AuthorizationRequest)
                    SerializationUtils.deserialize(Base64.getUrlDecoder().decode(serialized));

            assertThat(deserialized.getClientId()).isEqualTo("client-123");
            assertThat(deserialized.getAuthorizationUri().toString()).isEqualTo("https://auth.provider.com/authorize");
            assertThat(deserialized.getRedirectUri()).isEqualTo("http://app.example.com/oauth/callback");
            assertThat(deserialized.getState()).isEqualTo("unique-state-value");
            assertThat(deserialized.getScopes()).containsExactlyInAnyOrder("openid", "profile", "email");
        }
    }
}
