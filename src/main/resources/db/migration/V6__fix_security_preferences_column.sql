-- V6: Fix column name mismatch in user_security_preferences table
-- The entity field 'require2faForSensitiveActions' maps to 'require2fa_for_sensitive_actions'
-- (Hibernate naming strategy doesn't add underscore before numbers)
-- But V4 migration created 'require_2fa_for_sensitive_actions' (with extra underscore)

ALTER TABLE user_security_preferences
CHANGE COLUMN require_2fa_for_sensitive_actions require2fa_for_sensitive_actions BOOLEAN DEFAULT FALSE;
