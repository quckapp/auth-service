package com.quckapp.auth.security.oauth2;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * OAuth2 Configuration Properties
 */
@Configuration
@ConfigurationProperties(prefix = "oauth2")
@Getter
@Setter
public class OAuth2Config {

    /**
     * Redirect URI after successful authentication
     */
    private String defaultSuccessUrl = "/";

    /**
     * Redirect URI after failed authentication
     */
    private String defaultFailureUrl = "/login?error=true";

    /**
     * Frontend callback URL for token delivery
     */
    private String frontendCallbackUrl = "http://localhost:3000/auth/callback";

    /**
     * Mobile app deep link scheme
     */
    private String mobileDeepLinkScheme = "quckapp://";

    /**
     * Allowed redirect URIs (for security validation)
     */
    private Map<String, String> authorizedRedirectUris = new HashMap<>();

    /**
     * Cookie name for storing redirect URI
     */
    private String redirectUriCookieName = "oauth2_redirect_uri";

    /**
     * Cookie expiration in seconds
     */
    private int cookieExpireSeconds = 180;
}
