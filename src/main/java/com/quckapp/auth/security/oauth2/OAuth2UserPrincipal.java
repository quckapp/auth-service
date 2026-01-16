package com.quckapp.auth.security.oauth2;

import com.quckapp.auth.domain.entity.AuthUser;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.*;

/**
 * Principal representing an OAuth2 authenticated user
 */
@Getter
public class OAuth2UserPrincipal implements OAuth2User, UserDetails {

    private final UUID id;
    private final String email;
    private final String password;
    private final String externalId;
    private final Collection<? extends GrantedAuthority> authorities;
    private final Map<String, Object> attributes;
    private final boolean isNewUser;

    private OAuth2UserPrincipal(UUID id, String email, String password, String externalId,
                                Collection<? extends GrantedAuthority> authorities,
                                Map<String, Object> attributes, boolean isNewUser) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.externalId = externalId;
        this.authorities = authorities;
        this.attributes = attributes;
        this.isNewUser = isNewUser;
    }

    /**
     * Create OAuth2UserPrincipal from AuthUser entity
     */
    public static OAuth2UserPrincipal create(AuthUser user, Map<String, Object> attributes, boolean isNewUser) {
        List<GrantedAuthority> authorities = Collections.singletonList(
                new SimpleGrantedAuthority("ROLE_USER")
        );

        return new OAuth2UserPrincipal(
                user.getId(),
                user.getEmail(),
                user.getPasswordHash(),
                user.getExternalId(),
                authorities,
                attributes,
                isNewUser
        );
    }

    // OAuth2User methods
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getName() {
        return String.valueOf(id);
    }

    // UserDetails methods
    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
