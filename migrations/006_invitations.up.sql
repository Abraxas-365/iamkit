-- Invitations: an operator invites an email address to an organization with
-- initial roles and groups. The raw token is shown once and delivered by the
-- mail webhook; only its SHA-256 is stored. Status is derived: accepted,
-- revoked, expired (expires_at passed) or pending. role_ids/group_ids carry
-- no foreign keys: roles or groups deleted before acceptance are skipped.
CREATE TABLE invitations (
  id               uuid        PRIMARY KEY,
  environment_id   uuid        NOT NULL,
  organization_id  uuid        NOT NULL,
  email            text        NOT NULL CHECK (email = lower(trim(email))),
  role_ids         uuid[]      NOT NULL DEFAULT '{}',
  group_ids        uuid[]      NOT NULL DEFAULT '{}',
  inviter          text        NOT NULL,
  token_hash       bytea       NOT NULL UNIQUE,
  expires_at       timestamptz NOT NULL,
  accepted_at      timestamptz,
  accepted_user_id uuid,
  revoked_at       timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  CHECK ((accepted_at IS NULL) = (accepted_user_id IS NULL)),
  CHECK (accepted_at IS NULL OR revoked_at IS NULL),
  FOREIGN KEY (organization_id, environment_id)
    REFERENCES organizations(id, environment_id)
);
-- One open invitation per organization and email; expired ones are revoked
-- before a new one is created (an index predicate cannot use now()).
CREATE UNIQUE INDEX invitations_pending ON invitations(organization_id, email)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX invitations_org ON invitations(environment_id, organization_id, created_at DESC);
CREATE INDEX invitations_email ON invitations(environment_id, email);

-- The customer's invitation page; the webhook gets link = url?token=…
ALTER TABLE delivery_configs ADD COLUMN invitation_url text NOT NULL DEFAULT '';
