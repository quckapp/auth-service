-- V7: Fix session_activities.details column type
-- The JSON column type requires valid JSON, but the service passes:
-- - NULL values (for SESSION_CREATED)
-- - Plain strings like "Test termination" (for SESSION_TERMINATED)
-- Change to TEXT to allow any string content

ALTER TABLE session_activities
MODIFY COLUMN details TEXT;
