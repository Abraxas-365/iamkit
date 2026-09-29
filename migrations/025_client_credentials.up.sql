-- 025: client_credentials for service accounts and private_key_jwt client
-- authentication (RFC 7523) for service accounts and OAuth clients.
--
-- Existing rows keep authenticating as before: confidential OAuth clients
-- and service accounts with their secret over HTTP Basic, public clients
-- with none.
ALTER TABLE oauth_clients
  ADD COLUMN token_endpoint_auth_method text NOT NULL DEFAULT 'client_secret_basic'
    CHECK (token_endpoint_auth_method IN ('none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt')),
  ADD COLUMN token_endpoint_auth_signing_alg text NOT NULL DEFAULT 'RS256'
    CHECK (token_endpoint_auth_signing_alg IN ('RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512')),
  ADD COLUMN jwks jsonb,
  ADD COLUMN jwks_uri text NOT NULL DEFAULT '';

-- Public clients always authenticate with none (the code enforces it).
UPDATE oauth_clients SET token_endpoint_auth_method = 'none' WHERE public;

ALTER TABLE service_accounts
  ADD COLUMN token_endpoint_auth_method text NOT NULL DEFAULT 'client_secret_basic'
    CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'private_key_jwt')),
  ADD COLUMN token_endpoint_auth_signing_alg text NOT NULL DEFAULT 'RS256'
    CHECK (token_endpoint_auth_signing_alg IN ('RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512')),
  ADD COLUMN jwks jsonb,
  ADD COLUMN jwks_uri text NOT NULL DEFAULT '';

-- Client assertions already used (jti replay protection), kept until the
-- assertion expires. hash = SHA-256 of the client-scoped jti.
CREATE TABLE client_assertion_jtis (
  hash       bytea       PRIMARY KEY,
  expires_at timestamptz NOT NULL
);
CREATE INDEX client_assertion_jtis_expires ON client_assertion_jtis (expires_at);
