-- SAML 2.0 identity providers as organization connections.
--
-- A SAML connection keeps the identity provider's entity ID as issuer and
-- the service provider's entity ID as client_id; it has no client secret.
ALTER TABLE federation_connections DROP CONSTRAINT federation_connections_provider_check;
ALTER TABLE federation_connections ADD CONSTRAINT federation_connections_provider_check
  CHECK (provider IN ('oidc','google','microsoft','github','apple','gitlab','github_enterprise','oauth2','saml'));
ALTER TABLE federation_connections DROP CONSTRAINT federation_connections_secret;
ALTER TABLE federation_connections ADD CONSTRAINT federation_connections_secret
  CHECK (CASE WHEN provider = 'saml' THEN secret_env IS NULL AND secret_sealed IS NULL
              ELSE (secret_env IS NULL) <> (secret_sealed IS NULL) END);
ALTER TABLE federation_connections ADD CONSTRAINT federation_connections_saml
  CHECK (provider <> 'saml' OR organization_id IS NOT NULL);

-- A SAML response posted to the assertion consumer service waits here for
-- the callback of the browser that started the login (the one with the
-- binding cookie). It lives as long as its state and is taken once.
CREATE TABLE saml_responses (
  handle_hash bytea       PRIMARY KEY,
  state_hash  bytea       NOT NULL REFERENCES federation_states(secret_hash) ON DELETE CASCADE,
  response    text        NOT NULL,
  expires_at  timestamptz NOT NULL
);
CREATE INDEX saml_responses_state ON saml_responses(state_hash);

-- Assertion IDs a connection accepted, until they expire: a replayed
-- assertion is refused.
CREATE TABLE saml_assertions (
  connection_id uuid        NOT NULL REFERENCES federation_connections(id),
  assertion_id  text        NOT NULL,
  expires_at    timestamptz NOT NULL,
  PRIMARY KEY (connection_id, assertion_id)
);
CREATE INDEX saml_assertions_expires ON saml_assertions(expires_at);
