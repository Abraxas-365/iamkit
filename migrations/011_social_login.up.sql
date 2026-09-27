-- Social login: provider presets, sign-up and email linking for
-- environment connections, and per-client sign-in options.
--
-- provider selects how IAMKit talks to the provider: generic OIDC
-- discovery, or a preset (Google, Microsoft, GitHub, Apple) whose issuer
-- IAMKit derives. options holds preset settings (Microsoft tenant policy,
-- Apple team and key IDs) and never secrets.
ALTER TABLE federation_connections
  ADD COLUMN provider text NOT NULL DEFAULT 'oidc'
    CHECK (provider IN ('oidc','google','microsoft','github','apple')),
  ADD COLUMN options jsonb NOT NULL DEFAULT '{}',
  -- Environment connections only: create an account for an unknown verified
  -- email (signup) in signup_organization_id, optionally in a group, and/or
  -- link the provider identity to the existing account with the same
  -- verified email (link_email).
  ADD COLUMN signup                 boolean NOT NULL DEFAULT false,
  ADD COLUMN link_email             boolean NOT NULL DEFAULT false,
  ADD COLUMN signup_organization_id uuid,
  ADD COLUMN signup_group_id        uuid,
  ADD CONSTRAINT federation_connections_social
    CHECK (organization_id IS NULL OR (NOT signup AND NOT link_email AND signup_organization_id IS NULL)),
  ADD CONSTRAINT federation_connections_signup
    CHECK ((signup = (signup_organization_id IS NOT NULL)) AND (signup_group_id IS NULL OR signup)),
  ADD CONSTRAINT federation_connections_signup_organization
    FOREIGN KEY (signup_organization_id, environment_id) REFERENCES organizations(id, environment_id),
  ADD CONSTRAINT federation_connections_signup_group
    FOREIGN KEY (signup_group_id, environment_id, signup_organization_id)
    REFERENCES groups(id, environment_id, organization_id) ON DELETE SET NULL (signup_group_id);

-- How an external identity was linked: by an operator, organization JIT,
-- matching verified email, or social sign-up.
ALTER TABLE external_identities DROP CONSTRAINT external_identities_origin_check;
ALTER TABLE external_identities ADD CONSTRAINT external_identities_origin_check
  CHECK (origin IN ('linked','jit','email','signup'));

-- Which sign-in methods a hosted client offers. No row: all of them.
-- connections lists the environment connections shown as buttons when
-- all_connections is off.
CREATE TABLE client_sign_in (
  client_id        uuid        PRIMARY KEY,
  environment_id   uuid        NOT NULL,
  password         boolean     NOT NULL,
  email_code       boolean     NOT NULL,
  organization_sso boolean     NOT NULL,
  all_connections  boolean     NOT NULL,
  connections      uuid[]      NOT NULL DEFAULT '{}',
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (client_id, environment_id) REFERENCES oauth_clients(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX client_sign_in_environment ON client_sign_in(environment_id);

-- A consumed state drops its continuation: an environment connection's
-- state (no organization) must still be consumable.
ALTER TABLE federation_states DROP CONSTRAINT federation_states_check;
ALTER TABLE federation_states ADD CONSTRAINT federation_states_check
  CHECK (organization_id IS NOT NULL OR continuation IS NOT NULL OR consumed_at IS NOT NULL);
