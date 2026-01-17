package com.quckapp.auth.service;

import com.quckapp.auth.dto.*;

/**
 * Authentication Service Interface
 */
public interface AuthService {

    AuthResponse register(RegisterRequest request, ClientInfo clientInfo);

    AuthResponse login(LoginRequest request, ClientInfo clientInfo);

    AuthResponse loginWith2FA(TwoFactorLoginRequest request, ClientInfo clientInfo);

    void logout(String token, ClientInfo clientInfo);

    TokenResponse refreshToken(RefreshTokenRequest request, ClientInfo clientInfo);

    TokenValidationResponse validateToken(TokenValidationRequest request);

    void revokeToken(String token, RevokeTokenRequest request, ClientInfo clientInfo);

    void revokeAllTokens(String token, ClientInfo clientInfo);

    void forgotPassword(ForgotPasswordRequest request, ClientInfo clientInfo);

    void resetPassword(ResetPasswordRequest request, ClientInfo clientInfo);

    void changePassword(String token, ChangePasswordRequest request, ClientInfo clientInfo);

    AuthResponse oauthLogin(String provider, OAuthRequest request, ClientInfo clientInfo);

    void linkOAuthProvider(String token, String provider, OAuthRequest request, ClientInfo clientInfo);

    void unlinkOAuthProvider(String token, String provider, ClientInfo clientInfo);

    SessionsResponse getActiveSessions(String token);

    void terminateSession(String token, String sessionId, ClientInfo clientInfo);

    void terminateAllOtherSessions(String token, ClientInfo clientInfo);
}
