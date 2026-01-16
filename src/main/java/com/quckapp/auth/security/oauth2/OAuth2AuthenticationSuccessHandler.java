package com.quckapp.auth.security.oauth2;

import com.quckapp.auth.domain.entity.AuthUser;
import com.quckapp.auth.domain.entity.RefreshToken;
import com.quckapp.auth.domain.repository.AuthUserRepository;
import com.quckapp.auth.domain.repository.RefreshTokenRepository;
import com.quckapp.auth.security.jwt.JwtOperations;
import com.quckapp.auth.service.LoginHistoryService;
import com.quckapp.auth.dto.LoginHistoryDtos.RecordLoginRequest;
import com.quckapp.auth.domain.entity.LoginMethod;
import com.quckapp.auth.domain.entity.LoginStatus;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

/**
 * Handler for successful OAuth2 authentication
 * Generates JWT tokens and redirects to frontend with tokens
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtOperations jwtService;
    private final AuthUserRepository authUserRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final LoginHistoryService loginHistoryService;
    private final OAuth2Config oAuth2Config;
    private final HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    private static final int REFRESH_TOKEN_EXPIRY_DAYS = 7;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        log.info("OAuth2 authentication success");

        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to {}", targetUrl);
            return;
        }

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        Optional<String> redirectUri = getCookieValue(request, oAuth2Config.getRedirectUriCookieName());

        String targetUrl = redirectUri.orElse(oAuth2Config.getFrontendCallbackUrl());

        // Get the authenticated user
        AuthUser user = getAuthUser(authentication);

        if (user == null) {
            log.error("Could not find authenticated user");
            return UriComponentsBuilder.fromUriString(targetUrl)
                    .queryParam("error", "user_not_found")
                    .build().toUriString();
        }

        // Generate tokens
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        // Save refresh token
        saveRefreshToken(user, refreshToken, request);

        // Record login
        recordOAuthLogin(user, request);

        // Check if new user
        boolean isNewUser = isNewUser(authentication);

        log.info("OAuth2 login successful for user: {}, new user: {}", user.getEmail(), isNewUser);

        // Build redirect URL with tokens
        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("access_token", accessToken)
                .queryParam("refresh_token", refreshToken)
                .queryParam("token_type", "Bearer")
                .queryParam("expires_in", jwtService.getAccessTokenExpiration())
                .queryParam("new_user", isNewUser)
                .build().toUriString();
    }

    private AuthUser getAuthUser(Authentication authentication) {
        Object principal = authentication.getPrincipal();

        if (principal instanceof CustomOidcUser customOidcUser) {
            return customOidcUser.getAuthUser();
        } else if (principal instanceof OAuth2UserPrincipal oAuth2UserPrincipal) {
            return authUserRepository.findById(oAuth2UserPrincipal.getId()).orElse(null);
        } else if (principal instanceof OidcUser oidcUser) {
            // Fallback - find by email
            String email = oidcUser.getEmail();
            return authUserRepository.findByEmail(email).orElse(null);
        }

        return null;
    }

    private boolean isNewUser(Authentication authentication) {
        Object principal = authentication.getPrincipal();

        if (principal instanceof CustomOidcUser customOidcUser) {
            return customOidcUser.isNewUser();
        } else if (principal instanceof OAuth2UserPrincipal oAuth2UserPrincipal) {
            return oAuth2UserPrincipal.isNewUser();
        }

        return false;
    }

    private void saveRefreshToken(AuthUser user, String refreshToken, HttpServletRequest request) {
        RefreshToken token = RefreshToken.builder()
                .user(user)
                .token(refreshToken)
                .expiresAt(Instant.now().plus(REFRESH_TOKEN_EXPIRY_DAYS, ChronoUnit.DAYS))
                .ipAddress(getClientIp(request))
                .userAgent(request.getHeader("User-Agent"))
                .build();

        refreshTokenRepository.save(token);
    }

    private void recordOAuthLogin(AuthUser user, HttpServletRequest request) {
        try {
            RecordLoginRequest loginRequest = RecordLoginRequest.builder()
                    .userId(user.getId())
                    .email(user.getEmail())
                    .loginStatus(LoginStatus.SUCCESS)
                    .loginMethod(LoginMethod.OAUTH)
                    .ipAddress(getClientIp(request))
                    .userAgent(request.getHeader("User-Agent"))
                    .build();

            loginHistoryService.recordLogin(loginRequest);
        } catch (Exception e) {
            log.warn("Failed to record OAuth login: {}", e.getMessage());
        }
    }

    private void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
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

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }
}
