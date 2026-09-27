-- 008: multi-factor authentication (TOTP + recovery codes).
--
-- A user has at most one TOTP factor. It is created unconfirmed (secret
-- sealed with IAMKIT_ENCRYPTION_KEY) and becomes active once the user
-- proves a code; last_step rejects a code being used twice.
CREATE TABLE user_factors (
  id             uuid        PRIMARY KEY,
  environment_id uuid        NOT NULL,
  user_id        uuid        NOT NULL,
  kind           text        NOT NULL CHECK (kind IN ('totp')),
  secret_sealed  text        NOT NULL,
  confirmed_at   timestamptz,
  last_step      bigint      NOT NULL DEFAULT 0,
  last_used_at   timestamptz,
  -- Wrong codes across every login, pending token and self-service call;
  -- reaching config.MFAFailures locks the factor until locked_until.
  failed_attempts int        NOT NULL DEFAULT 0,
  locked_until   timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (environment_id, user_id, kind),
  FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);

-- Single-use recovery codes, stored hashed. Regenerating replaces them all.
CREATE TABLE recovery_codes (
  environment_id uuid        NOT NULL,
  user_id        uuid        NOT NULL,
  code_hash      bytea       NOT NULL,
  used_at        timestamptz,
  PRIMARY KEY (environment_id, user_id, code_hash),
  FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);

-- A headless login that passed its first factor and waits for the second
-- (ik_mfa_ token, stored hashed). enroll: the organization requires MFA and
-- the user has no factor yet, so the token may enroll one.
CREATE TABLE mfa_logins (
  token_hash      bytea       PRIMARY KEY,
  environment_id  uuid        NOT NULL,
  organization_id uuid        NOT NULL,
  application_id  uuid        NOT NULL,
  resource_id     uuid        NOT NULL,
  user_id         uuid        NOT NULL,
  amr             text[]      NOT NULL,
  enroll          boolean     NOT NULL DEFAULT false,
  attempts        int         NOT NULL DEFAULT 0,
  expires_at      timestamptz NOT NULL,
  FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id)
);
CREATE INDEX mfa_logins_expires ON mfa_logins (expires_at);
CREATE INDEX mfa_logins_user ON mfa_logins (user_id, environment_id);

-- mfa_required: every password or email-code login into the organization
-- needs a second factor (users without one enroll during login).
-- mfa_for_federated: single sign-on logins follow the same rules instead of
-- trusting the identity provider's MFA.
ALTER TABLE organizations
  ADD COLUMN mfa_required      boolean NOT NULL DEFAULT false,
  ADD COLUMN mfa_for_federated boolean NOT NULL DEFAULT false;

-- How the session was authenticated (RFC 8176 style: pwd, email, fed, otp,
-- mfa); copied into the amr token claim.
ALTER TABLE sessions ADD COLUMN amr text[] NOT NULL DEFAULT '{}';

-- Hosted login progress: second-factor methods passed so far, the chosen
-- organization (kept while the second factor is asked) and wrong codes.
ALTER TABLE hosted_logins
  ADD COLUMN amr text[] NOT NULL DEFAULT '{}',
  ADD COLUMN chosen_organization_id uuid,
  ADD COLUMN mfa_attempts int NOT NULL DEFAULT 0,
  ADD FOREIGN KEY (chosen_organization_id, environment_id) REFERENCES organizations(id, environment_id);
