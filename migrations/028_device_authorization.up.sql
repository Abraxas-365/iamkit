-- 028: OAuth 2.0 Device Authorization Grant (RFC 8628).
--
-- grant_types lists what a client may use at the token endpoint. Existing
-- clients keep exactly what they could do before (authorization code and
-- refresh token).
ALTER TABLE oauth_clients
  ADD COLUMN grant_types text[] NOT NULL DEFAULT '{authorization_code,refresh_token}';

-- A device authorization: the device polls with device_code, the user types
-- user_code at /hosted/device. Both are stored as SHA-256 hashes. status
-- moves pending → approved (hosted login finished) or denied, and approved
-- → consumed when the device collects its tokens (single use).
CREATE TABLE oauth_device_codes (
  device_hash      bytea       PRIMARY KEY,
  user_hash        bytea       NOT NULL UNIQUE,
  environment_id   uuid        NOT NULL,
  client_id        uuid        NOT NULL,
  scope            text        NOT NULL,
  status           text        NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','denied','consumed')),
  interval_seconds integer     NOT NULL,
  last_poll_at     timestamptz,
  session_id       uuid,
  user_id          uuid,
  organization_id  uuid,
  expires_at       timestamptz NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (client_id, environment_id)
    REFERENCES oauth_clients(id, environment_id)
);
CREATE INDEX oauth_device_codes_expiry ON oauth_device_codes (expires_at);

-- A device approval runs the ordinary hosted journey on an authorization
-- ticket linked to the device code instead of an authorize request.
ALTER TABLE oauth_authorizations
  ADD COLUMN device_hash bytea REFERENCES oauth_device_codes(device_hash) ON DELETE CASCADE;
