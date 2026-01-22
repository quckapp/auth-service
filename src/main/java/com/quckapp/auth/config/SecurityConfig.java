package com.quckapp.auth.config;

import com.quckapp.auth.security.apikey.ApiKeyAuthenticationFilter;
import com.quckapp.auth.security.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ApiKeyAuthenticationFilter apiKeyAuthenticationFilter;

    /**
     * Security filter chain for REST API endpoints.
     * This chain handles all API requests with stateless JWT authentication.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher("/**")
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .authorizeHttpRequests(auth -> auth
                        // Public POST endpoints - Authentication
                        .requestMatchers(HttpMethod.POST, "/v1/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/login/2fa").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/register").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/token/refresh").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/token/validate").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/password/forgot").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/password/reset").permitAll()
                        // Phone OTP Authentication (all methods)
                        .requestMatchers("/v1/auth/phone/**").permitAll()
                        // OAuth endpoints (all methods)
                        .requestMatchers("/v1/oauth/**").permitAll()
                        // OAuth2 browser flow endpoints
                        .requestMatchers("/oauth2/**").permitAll()
                        .requestMatchers("/login/oauth2/**").permitAll()
                        // Health & Actuator
                        .requestMatchers("/actuator/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/health").permitAll()
                        // API Docs & Swagger
                        .requestMatchers("/v3/api-docs/**").permitAll()
                        .requestMatchers("/swagger-ui/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/swagger-ui.html").permitAll()
                        // Internal endpoints (authenticated via API Key)
                        .requestMatchers("/v1/internal/**").hasRole("API_KEY")
                        .requestMatchers("/v1/migration/**").hasRole("API_KEY")
                        .requestMatchers("/v1/users/internal/**").hasRole("API_KEY")
                        // All other requests require authentication
                        .anyRequest().authenticated())
                // API Key filter runs first for internal endpoints
                .addFilterBefore(apiKeyAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
