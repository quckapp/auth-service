package com.quckapp.auth.security.oauth2;

import com.quckapp.auth.domain.entity.AuthUser;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.Map;
import java.util.UUID;

/**
 * Custom OIDC User wrapper that includes our AuthUser
 */
@Getter
public class CustomOidcUser implements OidcUser {

    private final AuthUser authUser;
    private final OidcUser oidcUser;
    private final boolean newUser;

    public CustomOidcUser(AuthUser authUser, OidcUser oidcUser, boolean newUser) {
        this.authUser = authUser;
        this.oidcUser = oidcUser;
        this.newUser = newUser;
    }

    public UUID getUserId() {
        return authUser.getId();
    }

    public String getExternalId() {
        return authUser.getExternalId();
    }

    @Override
    public Map<String, Object> getClaims() {
        return oidcUser.getClaims();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return oidcUser.getUserInfo();
    }

    @Override
    public OidcIdToken getIdToken() {
        return oidcUser.getIdToken();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return oidcUser.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return oidcUser.getAuthorities();
    }

    @Override
    public String getName() {
        return authUser.getId().toString();
    }
}
