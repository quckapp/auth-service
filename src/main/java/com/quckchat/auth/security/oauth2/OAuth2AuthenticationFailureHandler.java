package com.quckapp.auth.security.oauth2;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Handler for failed OAuth2 authentication
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final OAuth2Config oAuth2Config;
    private final HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        log.error("OAuth2 authentication failed: {}", exception.getMessage());

        String targetUrl = getTargetUrl(request, exception);

        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private String getTargetUrl(HttpServletRequest request, AuthenticationException exception) {
        Optional<String> redirectUri = getCookieValue(request, oAuth2Config.getRedirectUriCookieName());
        String targetUrl = redirectUri.orElse(oAuth2Config.getDefaultFailureUrl());

        String errorMessage = exception.getLocalizedMessage();
        String errorCode = getErrorCode(exception);

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("error", errorCode)
                .queryParam("error_description", URLEncoder.encode(errorMessage, StandardCharsets.UTF_8))
                .build().toUriString();
    }

    private String getErrorCode(AuthenticationException exception) {
        String message = exception.getMessage();
        if (message != null) {
            if (message.contains("email_not_found")) {
                return "email_not_found";
            } else if (message.contains("processing_error")) {
                return "processing_error";
            } else if (message.contains("invalid_token")) {
                return "invalid_token";
            }
        }
        return "authentication_failed";
    }

    private Optional<String> getCookieValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (name.equals(cookie.getName())) {
                    return Optional.of(cookie.getValue());
                }
            }
        }
        return Optional.empty();
    }
}
