-- SCIM identity lifecycle: email aliases, userName rename, anchor provenance,
-- soft deprovisioning and opt-in adoption of existing organization members.

-- Anchor provenance: 'client' = externalId supplied by the directory (immutable),
-- 'derived' = IAMKit's own key (the user id) because the directory omitted it;
-- upgradable once to a client value. deprovisioned_at marks a SCIM DELETE: the
-- identity is hidden until the directory creates it again. version guards
-- read-modify-write PATCH requests against concurrent updates.
ALTER TABLE provisioned_identities
  ADD COLUMN external_id_source text NOT NULL DEFAULT 'client'
    CHECK (external_id_source IN ('client','derived')),
  ADD COLUMN deprovisioned_at timestamptz,
  ADD COLUMN version bigint NOT NULL DEFAULT 0,
  -- How the user joined the connection: 'created' by SCIM, 'adopted' by the
  -- adopt_existing_members policy or 'linked' by an operator. Only users the
  -- directory created may have their login email renamed by it.
  ADD COLUMN origin text NOT NULL DEFAULT 'linked'
    CHECK (origin IN ('created','adopted','linked')),
  ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
-- Before this migration, SCIM-created users had no password; others were linked.
UPDATE provisioned_identities i SET origin = 'created'
  FROM users u WHERE u.id = i.user_id AND u.environment_id = i.environment_id AND u.password_hash = '';
-- Earlier releases anchored identities without externalId by their email,
-- which broke on rename; re-key them by user id.
UPDATE provisioned_identities i SET external_id_source = 'derived', external_id = i.user_id::text
  FROM users u WHERE u.id = i.user_id AND u.environment_id = i.environment_id AND i.external_id = u.email;

-- Secondary addresses a directory reports for its identities (SCIM emails[]
-- minus userName). They belong to the connection, not to the user: they are
-- not login identifiers, never reserve an address in the environment and one
-- directory cannot see or change another directory's aliases.
CREATE TABLE provisioned_emails (
  connection_id  uuid NOT NULL,
  environment_id uuid NOT NULL,
  user_id        uuid NOT NULL,
  email          text NOT NULL CHECK (email = lower(trim(email))),
  type           text NOT NULL DEFAULT 'other',
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (connection_id, user_id, email),
  FOREIGN KEY (connection_id, user_id)
    REFERENCES provisioned_identities(connection_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX provisioned_emails_lookup ON provisioned_emails(connection_id, email);

-- Opt-in: SCIM create of an address owned by an existing member of the
-- connection's organization links that member instead of failing with 409.
ALTER TABLE provisioning_connections
  ADD COLUMN adopt_existing_members boolean NOT NULL DEFAULT false;
