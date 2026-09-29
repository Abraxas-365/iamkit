-- Which sign-in methods an environment allows, and its default second-factor
-- rules. No row keeps today's behaviour: every method allowed, password reset
-- offered, no second factor unless an organization requires one.
CREATE TABLE sign_in_policies (
  environment_id       uuid        PRIMARY KEY REFERENCES environments(id),
  allow_password       boolean     NOT NULL,
  allow_email_code     boolean     NOT NULL,
  -- Environment (social) connections; organization SSO follows its own
  -- enforcement instead.
  allow_social         boolean     NOT NULL,
  allow_password_reset boolean     NOT NULL,
  -- OR-ed with the organization's mfa_required / mfa_for_federated.
  mfa_required         boolean     NOT NULL,
  mfa_for_federated    boolean     NOT NULL,
  updated_at           timestamptz NOT NULL DEFAULT now()
);

-- An organization may only narrow the environment's methods.
ALTER TABLE organizations
  ADD COLUMN allow_password   boolean NOT NULL DEFAULT true,
  ADD COLUMN allow_email_code boolean NOT NULL DEFAULT true,
  ADD COLUMN allow_social     boolean NOT NULL DEFAULT true;

-- Password requirements an organization adds to the environment's policy.
-- Users are environment-wide with one password, so a member's policy is the
-- environment's tightened by every organization they are an active member
-- of. min_length 0 and max_age_days 0 add nothing.
CREATE TABLE organization_password_policies (
  organization_id uuid        PRIMARY KEY,
  environment_id  uuid        NOT NULL,
  min_length      int         NOT NULL CHECK (min_length = 0 OR min_length BETWEEN 8 AND 72),
  require_upper   boolean     NOT NULL,
  require_lower   boolean     NOT NULL,
  require_digit   boolean     NOT NULL,
  require_symbol  boolean     NOT NULL,
  max_age_days    int         NOT NULL CHECK (max_age_days BETWEEN 0 AND 3650),
  breach_check    boolean     NOT NULL,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX organization_password_policies_environment ON organization_password_policies(environment_id);
