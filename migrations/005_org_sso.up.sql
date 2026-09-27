-- Organization-scoped SSO.
--
-- A federation connection may belong to one organization (organization_id)
-- or, as before, serve the whole environment (NULL). Organization
-- connections can provision users just in time (restricted to the
-- organization's verified domains) and can be enforced: password and email
-- code login are then refused for emails on the organization's verified
-- domains, except for memberships with the break-glass sso_bypass flag.
--
-- Client secrets are either a legacy reference to an approved deployment
-- variable (secret_env + FEDERATION_CREDENTIAL_BINDINGS) or stored encrypted
-- with IAMKIT_ENCRYPTION_KEY (secret_sealed) — exactly one of the two.
ALTER TABLE federation_connections
  ADD COLUMN organization_id  uuid,
  ADD COLUMN secret_sealed    text,
  ALTER COLUMN secret_env DROP NOT NULL,
  ADD COLUMN jit_provisioning boolean     NOT NULL DEFAULT false,
  ADD COLUMN jit_group_id     uuid,
  ADD COLUMN enforcement      text        NOT NULL DEFAULT 'optional'
    CHECK (enforcement IN ('optional','enforced')),
  ADD COLUMN created_at       timestamptz NOT NULL DEFAULT now(),
  ADD CONSTRAINT federation_connections_secret
    CHECK ((secret_env IS NULL) <> (secret_sealed IS NULL)),
  ADD CONSTRAINT federation_connections_org_features
    CHECK (organization_id IS NOT NULL OR (NOT jit_provisioning AND jit_group_id IS NULL AND enforcement = 'optional')),
  ADD CONSTRAINT federation_connections_organization
    FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id),
  ADD CONSTRAINT federation_connections_jit_group
    FOREIGN KEY (jit_group_id, environment_id, organization_id)
    REFERENCES groups(id, environment_id, organization_id) ON DELETE SET NULL (jit_group_id);

-- At most one active enforced connection per organization.
CREATE UNIQUE INDEX federation_connections_enforced
  ON federation_connections(organization_id) WHERE enforcement = 'enforced' AND active;
CREATE INDEX federation_connections_org
  ON federation_connections(environment_id, organization_id) WHERE organization_id IS NOT NULL;

-- One IdP application (issuer + client) may serve several organizations:
-- subjects are linked per connection and JIT is limited to each
-- organization's verified domains. Uniqueness is now per organization, with
-- environment-wide connections sharing one scope.
ALTER TABLE federation_connections DROP CONSTRAINT federation_connections_environment_id_issuer_client_id_key;
CREATE UNIQUE INDEX federation_connections_client
  ON federation_connections(environment_id, COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), issuer, client_id);

-- Break-glass: members allowed to keep using password/email code login while
-- their organization enforces SSO.
ALTER TABLE memberships ADD COLUMN sso_bypass boolean NOT NULL DEFAULT false;

-- How an external identity was linked: by an operator or on first login.
ALTER TABLE external_identities
  ADD COLUMN origin     text        NOT NULL DEFAULT 'linked' CHECK (origin IN ('linked','jit')),
  ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
