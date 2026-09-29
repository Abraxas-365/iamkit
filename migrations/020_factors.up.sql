-- 020: several second factors per user.
--
-- Kinds widen to email and SMS codes and WebAuthn credentials. TOTP, email
-- and SMS stay one per user; a user may register several WebAuthn
-- credentials (name tells them apart, data holds the public credential).
-- Only TOTP keeps a sealed secret.
ALTER TABLE user_factors
  DROP CONSTRAINT user_factors_kind_check,
  ADD CONSTRAINT user_factors_kind_check CHECK (kind IN ('totp','email','sms','webauthn')),
  DROP CONSTRAINT user_factors_environment_id_user_id_kind_key,
  ALTER COLUMN secret_sealed DROP NOT NULL,
  ADD CONSTRAINT user_factors_secret CHECK (kind <> 'totp' OR secret_sealed IS NOT NULL),
  ADD COLUMN name text NOT NULL DEFAULT '',
  ADD COLUMN data jsonb NOT NULL DEFAULT '{}';
CREATE UNIQUE INDEX user_factors_single ON user_factors (environment_id, user_id, kind)
  WHERE kind IN ('totp','email','sms');

-- Wrong second-factor codes count per user, not per factor: switching to
-- another factor must not reset the count. Reaching config.MFAFailures
-- locks every factor until locked_until.
CREATE TABLE user_mfa_state (
  environment_id  uuid        NOT NULL,
  user_id         uuid        NOT NULL,
  failed_attempts int         NOT NULL DEFAULT 0,
  locked_until    timestamptz,
  PRIMARY KEY (environment_id, user_id),
  FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
INSERT INTO user_mfa_state (environment_id, user_id, failed_attempts, locked_until)
  SELECT environment_id, user_id, failed_attempts, locked_until FROM user_factors
  WHERE kind = 'totp' AND (failed_attempts > 0 OR locked_until IS NOT NULL);
ALTER TABLE user_factors DROP COLUMN failed_attempts, DROP COLUMN locked_until;
