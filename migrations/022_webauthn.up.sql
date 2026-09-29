-- 022: WebAuthn security keys (second factor) and passkeys (first factor).
--
-- A WebAuthn factor keeps its public credential in data (public key, sign
-- count, AAGUID, transports, backup flags); credential_id is the
-- authenticator's credential id, unique per environment so a passkey
-- names exactly one user. passkey marks a discoverable credential that
-- verified the user: it may sign in on its own.
ALTER TABLE user_factors
  ADD COLUMN credential_id bytea,
  ADD COLUMN passkey       boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT user_factors_credential CHECK (kind <> 'webauthn' OR credential_id IS NOT NULL);
CREATE UNIQUE INDEX user_factors_credential_id ON user_factors (environment_id, credential_id)
  WHERE credential_id IS NOT NULL;

-- A WebAuthn ceremony between its options and the browser's answer: the
-- challenge (hashed id), who it is for (none for a passkey login, which
-- learns the user from the credential) and the library's session data.
-- Single use; expires after config.WebAuthnCeremonyTTL.
CREATE TABLE webauthn_sessions (
  id_hash        bytea       PRIMARY KEY,
  environment_id uuid        NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  user_id        uuid,
  purpose        text        NOT NULL CHECK (purpose IN ('register','login','passkey')),
  data           jsonb       NOT NULL,
  expires_at     timestamptz NOT NULL,
  FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX webauthn_sessions_expires ON webauthn_sessions (expires_at);

-- Passkeys as a sign-in method: allowed by default for the environment and
-- organizations; hosted clients that already chose their methods keep them
-- (a new client without options offers passkeys).
ALTER TABLE sign_in_policies ADD COLUMN allow_passkey boolean NOT NULL DEFAULT true;
ALTER TABLE organizations ADD COLUMN allow_passkey boolean NOT NULL DEFAULT true;
ALTER TABLE client_sign_in ADD COLUMN passkey boolean NOT NULL DEFAULT false;
ALTER TABLE hosted_logins DROP CONSTRAINT hosted_logins_method_check,
  ADD CONSTRAINT hosted_logins_method_check CHECK (method IN ('password','code','sso','passkey'));
