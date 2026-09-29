-- 024: signing keys per environment, with rotation.
--
-- Environments without a row here keep signing with the deployment key
-- (JWT_PRIVATE_KEY_PATH), whose kid is unchanged. An environment key signs
-- the environment's tokens once active; next keys are published in the
-- JWKS before they sign, retiring ones until the operator retires them.
-- The private key is sealed with IAMKIT_ENCRYPTION_KEY.
CREATE TABLE signing_keys (
  id             text        PRIMARY KEY, -- kid: SHA-256 of the public key (DER), 16 bytes, base64url
  environment_id uuid        NOT NULL REFERENCES environments(id),
  algorithm      text        NOT NULL DEFAULT 'RS256' CHECK (algorithm = 'RS256'),
  private_sealed text        NOT NULL,
  public_der     bytea       NOT NULL,
  state          text        NOT NULL CHECK (state IN ('next', 'active', 'retiring', 'retired')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  activated_at   timestamptz,
  retire_after   timestamptz,
  retired_at     timestamptz
);

-- At most one key signs per environment.
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys (environment_id) WHERE state = 'active';
CREATE INDEX signing_keys_environment ON signing_keys (environment_id, created_at DESC);
