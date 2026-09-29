-- 026: opaque OAuth access tokens per client.
--
-- Existing clients keep JWT access tokens. Opaque tokens (ory_at_…) are
-- resolved only by /oauth/introspect and /oauth/userinfo, which look the
-- token up by its signature without knowing the environment first.
ALTER TABLE oauth_clients
  ADD COLUMN access_token_format text NOT NULL DEFAULT 'jwt'
    CHECK (access_token_format IN ('jwt', 'opaque'));

CREATE INDEX oauth_requests_signature ON oauth_requests (kind, signature_hash);
