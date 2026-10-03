-- 059: Operators can require a user to choose a new password (F-054).
--
-- The next password sign-in answers like an expired password (hosted
-- "Choose a new password", PASSWORD_CHANGE_REQUIRED on /identity/v1/login);
-- setting a password clears the flag.
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_change_required boolean NOT NULL DEFAULT false;
