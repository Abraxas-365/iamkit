-- Self-registration: people create their own account with a verified email.
--
-- The environment's sign-in policy turns it on and names the organization
-- (and optionally a group, not SCIM-managed) every new account joins. The
-- organization is kept when sign-up is turned off.
ALTER TABLE sign_in_policies
  ADD COLUMN allow_signup           boolean NOT NULL DEFAULT false,
  ADD COLUMN signup_organization_id uuid,
  ADD COLUMN signup_group_id        uuid,
  ADD CONSTRAINT sign_in_policies_signup
    CHECK ((NOT allow_signup OR signup_organization_id IS NOT NULL) AND (signup_group_id IS NULL OR signup_organization_id IS NOT NULL)),
  ADD CONSTRAINT sign_in_policies_signup_organization
    FOREIGN KEY (signup_organization_id, environment_id) REFERENCES organizations(id, environment_id),
  ADD CONSTRAINT sign_in_policies_signup_group
    FOREIGN KEY (signup_group_id, environment_id, signup_organization_id)
    REFERENCES groups(id, environment_id, organization_id) ON DELETE SET NULL (signup_group_id);

-- A hosted client may leave out the "Create account" link.
ALTER TABLE client_sign_in ADD COLUMN signup boolean NOT NULL DEFAULT true;

-- Sign-ups waiting for their email code. No user exists until the code is
-- verified, so an unverified sign-up never holds an address. password_hash
-- is '' for a passwordless (email code) account. A newer sign-up for the
-- same email consumes older ones.
CREATE TABLE signups (
  id              uuid        PRIMARY KEY,
  environment_id  uuid        NOT NULL REFERENCES environments(id),
  email           text        NOT NULL,
  name            text        NOT NULL CHECK (length(trim(name)) > 0),
  password_hash   text        NOT NULL,
  secret_hash     bytea       NOT NULL,
  attempts        int         NOT NULL DEFAULT 0,
  expires_at      timestamptz NOT NULL,
  consumed_at     timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX signups_email ON signups(environment_id, email, created_at);
