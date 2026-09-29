-- Per-environment password rules. No row keeps the built-in behaviour:
-- 12-72 characters, no composition rules, no expiry, no lockout.
CREATE TABLE password_policies (
  environment_id    uuid        PRIMARY KEY REFERENCES environments(id),
  min_length        int         NOT NULL CHECK (min_length BETWEEN 8 AND 72),
  require_upper     boolean     NOT NULL,
  require_lower     boolean     NOT NULL,
  require_digit     boolean     NOT NULL,
  require_symbol    boolean     NOT NULL,
  -- 0 = passwords never expire.
  max_age_days      int         NOT NULL CHECK (max_age_days BETWEEN 0 AND 3650),
  -- 0 = no lockout; otherwise every lockout_threshold wrong passwords in a
  -- row lock the account for lockout_minutes, doubling up to a day.
  lockout_threshold int         NOT NULL CHECK (lockout_threshold BETWEEN 0 AND 100),
  lockout_minutes   int         NOT NULL CHECK (lockout_minutes BETWEEN 1 AND 1440),
  breach_check      boolean     NOT NULL,
  updated_at        timestamptz NOT NULL DEFAULT now()
);

-- Wrong passwords in a row (reset by a right one or a password reset), the
-- lock they caused, and when the password was last chosen (for expiry).
-- Existing passwords count from the account's creation.
ALTER TABLE users
  ADD COLUMN failed_logins       int         NOT NULL DEFAULT 0,
  ADD COLUMN locked_until        timestamptz,
  ADD COLUMN password_changed_at timestamptz;
UPDATE users SET password_changed_at = created_at;
ALTER TABLE users
  ALTER COLUMN password_changed_at SET DEFAULT now(),
  ALTER COLUMN password_changed_at SET NOT NULL;

-- A hosted login whose password expired waits for a new one before the
-- session is issued.
ALTER TABLE hosted_logins ADD COLUMN password_change boolean NOT NULL DEFAULT false;

-- A headless login that replaced its expired password keeps the new hash
-- here until its second factor passes; only then is it stored.
ALTER TABLE mfa_logins ADD COLUMN password_hash text NOT NULL DEFAULT '';
