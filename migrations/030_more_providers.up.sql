-- More upstream providers and linking options.
--
-- gitlab (OIDC; gitlab.com or a self-managed base_url), github_enterprise
-- (GitHub Enterprise Server at base_url) and oauth2 (any OAuth 2.0
-- provider: endpoints, scopes and a userinfo claim mapping in options).
ALTER TABLE federation_connections DROP CONSTRAINT federation_connections_provider_check;
ALTER TABLE federation_connections ADD CONSTRAINT federation_connections_provider_check
  CHECK (provider IN ('oidc','google','microsoft','github','apple','gitlab','github_enterprise','oauth2'));

-- update_profile refreshes a linked user's name (and, for passwordless
-- accounts no directory manages, the verified email) from the provider at
-- every sign-in.
ALTER TABLE federation_connections ADD COLUMN update_profile boolean NOT NULL DEFAULT false;

-- Organization connections may now link by email too: an unlinked identity
-- whose email is on the organization's verified domains signs in to the
-- existing member account with that email, without JIT creating accounts.
-- Sign-up stays an environment-connection setting.
ALTER TABLE federation_connections DROP CONSTRAINT federation_connections_social;
ALTER TABLE federation_connections ADD CONSTRAINT federation_connections_social
  CHECK (organization_id IS NULL OR (NOT signup AND signup_organization_id IS NULL));
