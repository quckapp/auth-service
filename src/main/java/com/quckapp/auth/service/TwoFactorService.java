package com.quckapp.auth.service;

import com.quckapp.auth.dto.*;

/**
 * Two-Factor Authentication Service Interface
 */
public interface TwoFactorService {

    TwoFactorSetupResponse setupTwoFactor(String token);

    TwoFactorEnableResponse enableTwoFactor(String token, TwoFactorEnableRequest request, ClientInfo clientInfo);

    void disableTwoFactor(String token, TwoFactorDisableRequest request, ClientInfo clientInfo);

    BackupCodesResponse generateBackupCodes(String token, TwoFactorVerifyRequest request, ClientInfo clientInfo);
}
