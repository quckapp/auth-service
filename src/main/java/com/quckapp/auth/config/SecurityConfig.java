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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

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
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
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
                        // Email OTP Authentication (public endpoints only)
                        .requestMatchers(HttpMethod.POST, "/v1/auth/email/request-otp").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/auth/email/verify-otp").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/auth/email/resend-otp").permitAll()
                        // OAuth endpoints (all methods)
                        .requestMatchers("/v1/oauth/**").permitAll()
                        // OAuth2 browser flow endpoints
                        .requestMatchers("/oauth2/**").permitAll()
                        .requestMatchers("/login/oauth2/**").permitAll()
                        // Health & Actuator
                        .requestMatchers("/actuator/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/health").permitAll()
                        // API Docs & Swagger
                        .requestMatchers("/v1/api-docs/**").permitAll()
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

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Allow Flutter web app origins (development)
        configuration.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://localhost:8080",
                "http://127.0.0.1:8080"
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
