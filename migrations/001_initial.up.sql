-- IAMKit consolidated schema. Represents the final state of migrations 001–017.
-- Requires an empty public schema; no legacy adoption.

-- ─── Management plane ────────────────────────────────────────────────
CREATE TABLE workspaces (
  id         uuid        PRIMARY KEY,
  name       text        NOT NULL CHECK (length(trim(name)) > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE operators (
  id            uuid        PRIMARY KEY,
  email         text        NOT NULL UNIQUE CHECK (email = lower(trim(email))),
  password_hash text        NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workspace_members (
  workspace_id uuid    NOT NULL REFERENCES workspaces(id),
  operator_id  uuid    NOT NULL REFERENCES operators(id),
  role         text    NOT NULL CHECK (role IN ('owner','admin','viewer')),
  active       boolean NOT NULL DEFAULT true,
  PRIMARY KEY (workspace_id, operator_id)
);

CREATE TABLE management_keys (
  id          uuid        PRIMARY KEY,
  workspace_id uuid       NOT NULL,
  operator_id  uuid       NOT NULL,
  secret_hash  bytea      NOT NULL UNIQUE,
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz,
  FOREIGN KEY (workspace_id, operator_id)
    REFERENCES workspace_members(workspace_id, operator_id)
);

CREATE TABLE operator_sessions (
  id           uuid        PRIMARY KEY,
  workspace_id uuid        NOT NULL,
  operator_id  uuid        NOT NULL,
  secret_hash  bytea       NOT NULL UNIQUE,
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz,
  FOREIGN KEY (workspace_id, operator_id)
    REFERENCES workspace_members(workspace_id, operator_id)
);

-- ─── Tenant hierarchy ────────────────────────────────────────────────
CREATE TABLE projects (
  id           uuid NOT NULL PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES workspaces(id),
  name         text NOT NULL,
  UNIQUE (id, workspace_id)
);

CREATE TABLE environments (
  id         uuid NOT NULL PRIMARY KEY,
  project_id uuid NOT NULL REFERENCES projects(id),
  name       text NOT NULL,
  UNIQUE (project_id, name)
);

-- ─── Identity ────────────────────────────────────────────────────────
CREATE TABLE users (
  id             uuid        PRIMARY KEY,
  environment_id uuid        NOT NULL REFERENCES environments(id),
  email          text        NOT NULL CHECK (email = lower(trim(email))),
  name           text        NOT NULL,
  password_hash  text        NOT NULL,
  active         boolean     NOT NULL DEFAULT true,
  email_verified boolean     NOT NULL DEFAULT false,
  metadata       jsonb       NOT NULL DEFAULT '{}',
  otp_enabled    boolean     NOT NULL DEFAULT false,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, environment_id),
  UNIQUE (environment_id, email)
);

CREATE TABLE organizations (
  id             uuid    PRIMARY KEY,
  environment_id uuid    NOT NULL REFERENCES environments(id),
  name           text    NOT NULL,
  active         boolean NOT NULL DEFAULT true,
  metadata       jsonb   NOT NULL DEFAULT '{}',
  UNIQUE (id, environment_id)
);

-- memberships — org_unit FK added after org_units table exists.
CREATE TABLE memberships (
  environment_id  uuid    NOT NULL,
  organization_id uuid    NOT NULL,
  user_id         uuid    NOT NULL,
  active          boolean NOT NULL DEFAULT true,
  org_unit_id     uuid,
  manager_id      uuid,
  display_name    text,
  PRIMARY KEY (organization_id, user_id),
  UNIQUE (environment_id, organization_id, user_id),
  FOREIGN KEY (organization_id, environment_id)
    REFERENCES organizations(id, environment_id),
  FOREIGN KEY (user_id, environment_id)
    REFERENCES users(id, environment_id),
  CONSTRAINT membership_manager
    FOREIGN KEY (environment_id, organization_id, manager_id)
    REFERENCES memberships(environment_id, organization_id, user_id),
  CONSTRAINT no_self_manager CHECK (manager_id IS DISTINCT FROM user_id)
);

-- ─── Organization structure ──────────────────────────────────────────
CREATE TABLE org_units (
  id              uuid PRIMARY KEY,
  environment_id  uuid NOT NULL,
  organization_id uuid NOT NULL,
  parent_id       uuid,
  name            text NOT NULL CHECK (length(trim(name)) > 0),
  kind            text NOT NULL,
  UNIQUE (environment_id, organization_id, id),
  FOREIGN KEY (organization_id, environment_id)
    REFERENCES organizations(id, environment_id),
  FOREIGN KEY (environment_id, organization_id, parent_id)
    REFERENCES org_units(environment_id, organization_id, id),
  CHECK (parent_id IS DISTINCT FROM id)
);

-- Deferred FK: memberships.org_unit_id → org_units
ALTER TABLE memberships
  ADD CONSTRAINT membership_unit
  FOREIGN KEY (environment_id, organization_id, org_unit_id)
  REFERENCES org_units(environment_id, organization_id, id);

CREATE TABLE positions (
  id              uuid PRIMARY KEY,
  environment_id  uuid NOT NULL,
  organization_id uuid NOT NULL,
  name            text NOT NULL CHECK (length(trim(name)) > 0),
  code            text NOT NULL,
  UNIQUE (environment_id, organization_id, id),
  UNIQUE (organization_id, code),
  FOREIGN KEY (organization_id, environment_id)
    REFERENCES organizations(id, environment_id)
);

CREATE TABLE position_assignments (
  id              uuid PRIMARY KEY,
  environment_id  uuid NOT NULL,
  organization_id uuid NOT NULL,
  position_id     uuid NOT NULL,
  user_id         uuid NOT NULL,
  org_unit_id     uuid,
  FOREIGN KEY (environment_id, organization_id, position_id)
    REFERENCES positions(environment_id, organization_id, id),
  FOREIGN KEY (environment_id, organization_id, user_id)
    REFERENCES memberships(environment_id, organization_id, user_id),
  FOREIGN KEY (environment_id, organization_id, org_unit_id)
    REFERENCES org_units(environment_id, organization_id, id)
);

-- ─── Applications & resources ────────────────────────────────────────
CREATE TABLE applications (
  id             uuid    PRIMARY KEY,
  environment_id uuid    NOT NULL REFERENCES environments(id),
  name           text    NOT NULL,
  redirect_uris  text[]  NOT NULL DEFAULT '{}',
  active         boolean NOT NULL DEFAULT true,
  UNIQUE (id, environment_id)
);

CREATE TABLE resources (
  id             uuid   PRIMARY KEY,
  environment_id uuid   NOT NULL REFERENCES environments(id),
  name           text   NOT NULL,
  prefix         text   NOT NULL
    CHECK (length(trim(prefix)) >= 1 AND prefix ~ '^[a-z][a-z0-9_-]*$'),
  audience       text   NOT NULL CHECK (length(trim(audience)) > 0),
  permissions    text[] NOT NULL DEFAULT '{}',
  UNIQUE (id, environment_id),
  UNIQUE (environment_id, audience),
  UNIQUE (environment_id, prefix)
);

CREATE TABLE application_resources (
  environment_id uuid NOT NULL,
  application_id uuid NOT NULL,
  resource_id    uuid NOT NULL,
  PRIMARY KEY (application_id, resource_id),
  UNIQUE (environment_id, application_id, resource_id),
  FOREIGN KEY (application_id, environment_id)
    REFERENCES applications(id, environment_id),
  FOREIGN KEY (resource_id, environment_id)
    REFERENCES resources(id, environment_id)
);

-- ─── Authorization ──────────────────────────────────────────────────
CREATE TABLE grants (
  id              uuid   PRIMARY KEY,
  environment_id  uuid   NOT NULL,
  organization_id uuid   NOT NULL,
  user_id         uuid   NOT NULL,
  resource_id     uuid   NOT NULL,
  permissions     text[] NOT NULL DEFAULT '{}',
  UNIQUE (organization_id, user_id, resource_id),
  FOREIGN KEY (environment_id, organization_id, user_id)
    REFERENCES memberships(environment_id, organization_id, user_id),
  FOREIGN KEY (resource_id, environment_id)
    REFERENCES resources(id, environment_id)
);

CREATE TABLE roles (
  id             uuid   PRIMARY KEY,
  environment_id uuid   NOT NULL,
  resource_id    uuid   NOT NULL,
  name           text   NOT NULL CHECK (length(trim(name)) > 0),
  permissions    text[] NOT NULL DEFAULT '{}',
  UNIQUE (environment_id, resource_id, id),
  UNIQUE (resource_id, name),
  FOREIGN KEY (resource_id, environment_id)
    REFERENCES resources(id, environment_id)
);

CREATE TABLE role_assignments (
  environment_id  uuid NOT NULL,
  organization_id uuid NOT NULL,
  user_id         uuid NOT NULL,
  resource_id     uuid NOT NULL,
  role_id         uuid NOT NULL,
  PRIMARY KEY (organization_id, user_id, role_id),
  FOREIGN KEY (environment_id, organization_id, user_id)
    REFERENCES memberships(environment_id, organization_id, user_id),
  FOREIGN KEY (environment_id, resource_id, role_id)
    REFERENCES roles(environment_id, resource_id, id) ON DELETE CASCADE
);

CREATE VIEW effective_grants AS
  SELECT environment_id, organization_id, user_id, resource_id,
    COALESCE(array_agg(DISTINCT permission)
      FILTER (WHERE permission IS NOT NULL), '{}') AS permissions
  FROM (
    SELECT g.environment_id, g.organization_id, g.user_id, g.resource_id, p.permission
      FROM grants g LEFT JOIN LATERAL unnest(g.permissions) p(permission) ON true
    UNION ALL
    SELECT a.environment_id, a.organization_id, a.user_id, a.resource_id, p.permission
      FROM role_assignments a JOIN roles r ON r.id = a.role_id
      LEFT JOIN LATERAL unnest(r.permissions) p(permission) ON true
  ) access
  GROUP BY environment_id, organization_id, user_id, resource_id;

-- ─── Sessions & tokens ──────────────────────────────────────────────
CREATE TABLE sessions (
  id                    uuid        PRIMARY KEY,
  environment_id        uuid        NOT NULL,
  organization_id       uuid        NOT NULL,
  user_id               uuid        NOT NULL,
  application_id        uuid        NOT NULL,
  resource_id           uuid        NOT NULL,
  expires_at            timestamptz NOT NULL,
  revoked_at            timestamptz,
  actor_id              uuid        REFERENCES operators(id),
  impersonation_reason  text,
  authenticated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, environment_id),
  FOREIGN KEY (environment_id, organization_id, user_id)
    REFERENCES memberships(environment_id, organization_id, user_id),
  FOREIGN KEY (environment_id, application_id, resource_id)
    REFERENCES application_resources(environment_id, application_id, resource_id),
  CONSTRAINT impersonation_attribution CHECK (
    (actor_id IS NULL AND impersonation_reason IS NULL)
    OR (actor_id IS NOT NULL AND length(trim(impersonation_reason)) >= 10)
  )
);

CREATE TABLE refresh_tokens (
  secret_hash    bytea       PRIMARY KEY,
  session_id     uuid        NOT NULL,
  environment_id uuid        NOT NULL,
  expires_at     timestamptz NOT NULL,
  used_at        timestamptz,
  FOREIGN KEY (session_id, environment_id)
    REFERENCES sessions(id, environment_id)
);

CREATE TABLE identity_challenges (
  id             uuid        PRIMARY KEY,
  environment_id uuid        NOT NULL,
  user_id        uuid        NOT NULL,
  purpose        text        NOT NULL CHECK (purpose IN ('login','password_reset','email_verification')),
  secret_hash    bytea       NOT NULL,
  expires_at     timestamptz NOT NULL,
  consumed_at    timestamptz,
  attempts       integer     NOT NULL DEFAULT 0,
  created_at     timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (user_id, environment_id)
    REFERENCES users(id, environment_id)
);

-- ─── Service accounts ───────────────────────────────────────────────
CREATE TABLE service_accounts (
  id             uuid        PRIMARY KEY,
  environment_id uuid        NOT NULL,
  application_id uuid        NOT NULL,
  resource_id    uuid        NOT NULL,
  name           text        NOT NULL,
  permissions    text[]      NOT NULL DEFAULT '{}',
  secret_hash    bytea       NOT NULL UNIQUE,
  expires_at     timestamptz NOT NULL,
  revoked_at     timestamptz,
  FOREIGN KEY (environment_id, application_id, resource_id)
    REFERENCES application_resources(environment_id, application_id, resource_id)
);

-- ─── Provisioning (SCIM) ────────────────────────────────────────────
CREATE TABLE provisioning_connections (
  id              uuid PRIMARY KEY,
  environment_id  uuid NOT NULL,
  organization_id uuid NOT NULL,
  name            text NOT NULL,
  UNIQUE (id, environment_id, organization_id),
  UNIQUE (id, environment_id),
  FOREIGN KEY (organization_id, environment_id)
    REFERENCES organizations(id, environment_id)
);

CREATE TABLE provisioning_credentials (
  id              uuid        PRIMARY KEY,
  environment_id  uuid        NOT NULL,
  organization_id uuid        NOT NULL,
  connection_id   uuid        NOT NULL,
  name            text        NOT NULL,
  secret_hash     bytea       NOT NULL UNIQUE,
  expires_at      timestamptz NOT NULL,
  revoked_at      timestamptz,
  UNIQUE (id, environment_id),
  FOREIGN KEY (organization_id, environment_id)
    REFERENCES organizations(id, environment_id),
  CONSTRAINT provisioning_connection
    FOREIGN KEY (connection_id, environment_id, organization_id)
    REFERENCES provisioning_connections(id, environment_id, organization_id)
);

CREATE TABLE provisioned_identities (
  connection_id  uuid NOT NULL,
  environment_id uuid NOT NULL,
  user_id        uuid NOT NULL,
  external_id    text NOT NULL,
  PRIMARY KEY (connection_id, external_id),
  UNIQUE (connection_id, user_id),
  FOREIGN KEY (connection_id, environment_id)
    REFERENCES provisioning_connections(id, environment_id),
  FOREIGN KEY (user_id, environment_id)
    REFERENCES users(id, environment_id)
);

-- ─── Federation (OIDC) ──────────────────────────────────────────────
CREATE TABLE federation_connections (
  id             uuid    PRIMARY KEY,
  environment_id uuid    NOT NULL REFERENCES environments(id),
  name           text    NOT NULL,
  issuer         text    NOT NULL,
  client_id      text    NOT NULL,
  secret_env     text    NOT NULL,
  active         boolean NOT NULL DEFAULT true,
  UNIQUE (id, environment_id),
  UNIQUE (environment_id, issuer, client_id)
);

CREATE TABLE external_identities (
  connection_id  uuid NOT NULL,
  environment_id uuid NOT NULL,
  subject        text NOT NULL,
  user_id        uuid NOT NULL,
  PRIMARY KEY (connection_id, subject),
  UNIQUE (connection_id, user_id),
  FOREIGN KEY (connection_id, environment_id)
    REFERENCES federation_connections(id, environment_id),
  FOREIGN KEY (user_id, environment_id)
    REFERENCES users(id, environment_id)
);

CREATE TABLE federation_states (
  secret_hash     bytea       PRIMARY KEY,
  connection_id   uuid        NOT NULL,
  environment_id  uuid        NOT NULL,
  organization_id uuid        NOT NULL,
  application_id  uuid        NOT NULL,
  resource_id     uuid        NOT NULL,
  binding_hash    bytea       NOT NULL,
  nonce           text        NOT NULL,
  verifier        text        NOT NULL,
  expires_at      timestamptz NOT NULL,
  consumed_at     timestamptz,
  FOREIGN KEY (connection_id, environment_id)
    REFERENCES federation_connections(id, environment_id),
  FOREIGN KEY (organization_id, environment_id)
    REFERENCES organizations(id, environment_id),
  FOREIGN KEY (environment_id, application_id, resource_id)
    REFERENCES application_resources(environment_id, application_id, resource_id)
);

-- ─── OAuth2 / OIDC ──────────────────────────────────────────────────
CREATE TABLE oauth_clients (
  id             uuid    PRIMARY KEY,
  environment_id uuid    NOT NULL,
  application_id uuid    NOT NULL,
  resource_id    uuid    NOT NULL,
  redirect_uris  text[]  NOT NULL,
  public         boolean NOT NULL,
  secret_hash    bytea   NOT NULL DEFAULT '',
  active         boolean NOT NULL DEFAULT true,
  UNIQUE (id, environment_id),
  FOREIGN KEY (environment_id, application_id, resource_id)
    REFERENCES application_resources(environment_id, application_id, resource_id)
);

CREATE TABLE oauth_requests (
  environment_id uuid    NOT NULL,
  kind           text    NOT NULL,
  signature_hash text    NOT NULL,
  client_id      uuid    NOT NULL,
  request_id     text    NOT NULL,
  data           jsonb   NOT NULL,
  expires_at     timestamptz NOT NULL,
  active         boolean NOT NULL DEFAULT true,
  PRIMARY KEY (environment_id, kind, signature_hash),
  FOREIGN KEY (client_id, environment_id)
    REFERENCES oauth_clients(id, environment_id)
);

CREATE TABLE oauth_authorizations (
  secret_hash  bytea       PRIMARY KEY,
  environment_id uuid      NOT NULL,
  client_id      uuid      NOT NULL,
  binding_hash   bytea     NOT NULL,
  request_form   text      NOT NULL,
  expires_at     timestamptz NOT NULL,
  consumed_at    timestamptz,
  requested_at   timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (client_id, environment_id)
    REFERENCES oauth_clients(id, environment_id)
);

-- ─── Delivery ────────────────────────────────────────────────────────
CREATE TABLE delivery_configs (
  environment_id uuid        PRIMARY KEY REFERENCES environments(id),
  webhook_url    text        NOT NULL,
  webhook_token  text        NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- ─── Audit ───────────────────────────────────────────────────────────
CREATE TABLE audit_events (
  id             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  environment_id uuid        NOT NULL REFERENCES environments(id),
  actor_id       uuid        NOT NULL,
  action         text        NOT NULL,
  target_id      text        NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);

-- ─── Functions ───────────────────────────────────────────────────────

-- Revocation is sticky: restoring a membership/grant never revives a session.
CREATE FUNCTION invalidate_identity_sessions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME = 'users' THEN
    UPDATE sessions SET revoked_at = now()
      WHERE environment_id = OLD.environment_id AND user_id = OLD.id AND revoked_at IS NULL;
  ELSIF TG_TABLE_NAME = 'organizations' THEN
    UPDATE sessions SET revoked_at = now()
      WHERE environment_id = OLD.environment_id AND organization_id = OLD.id AND revoked_at IS NULL;
  ELSIF TG_TABLE_NAME = 'applications' THEN
    UPDATE sessions SET revoked_at = now()
      WHERE environment_id = OLD.environment_id AND application_id = OLD.id AND revoked_at IS NULL;
  ELSIF TG_TABLE_NAME = 'roles' THEN
    UPDATE sessions s SET revoked_at = now()
      FROM role_assignments a
      WHERE a.role_id = OLD.id
        AND s.environment_id = a.environment_id AND s.organization_id = a.organization_id
        AND s.user_id = a.user_id AND s.resource_id = a.resource_id AND s.revoked_at IS NULL;
  ELSIF TG_TABLE_NAME = 'memberships' THEN
    UPDATE sessions SET revoked_at = now()
      WHERE environment_id = OLD.environment_id AND organization_id = OLD.organization_id
        AND user_id = OLD.user_id AND revoked_at IS NULL;
  ELSE
    UPDATE sessions SET revoked_at = now()
      WHERE environment_id = OLD.environment_id AND organization_id = OLD.organization_id
        AND user_id = OLD.user_id AND resource_id = OLD.resource_id AND revoked_at IS NULL;
  END IF;
  RETURN OLD;
END $$;

CREATE FUNCTION invalidate_identity_challenges() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE identity_challenges SET consumed_at = now()
    WHERE environment_id = OLD.environment_id AND user_id = OLD.id AND consumed_at IS NULL;
  RETURN NEW;
END $$;

-- Serialize every permission writer against the resource catalog.
CREATE FUNCTION enforce_permission_catalog() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE catalog text[];
BEGIN
  SELECT permissions INTO catalog
    FROM resources WHERE id = NEW.resource_id AND environment_id = NEW.environment_id FOR SHARE;
  IF catalog IS NULL OR NOT NEW.permissions <@ catalog THEN
    RAISE EXCEPTION 'permissions outside resource catalog' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION invalidate_otp_challenges() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE identity_challenges SET consumed_at = now()
    WHERE user_id = NEW.id AND environment_id = NEW.environment_id
      AND purpose = 'login' AND consumed_at IS NULL;
  RETURN NEW;
END $$;

-- ─── Triggers ────────────────────────────────────────────────────────

-- Session invalidation triggers (final state)
CREATE TRIGGER user_changed
  AFTER UPDATE ON users FOR EACH ROW
  WHEN ((OLD.active, OLD.password_hash, OLD.email)
    IS DISTINCT FROM (NEW.active, NEW.password_hash, NEW.email))
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TRIGGER organization_changed
  AFTER UPDATE ON organizations FOR EACH ROW
  WHEN (OLD.active IS DISTINCT FROM NEW.active)
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TRIGGER application_changed
  AFTER UPDATE ON applications FOR EACH ROW
  WHEN (OLD.active IS DISTINCT FROM NEW.active)
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TRIGGER membership_changed
  AFTER UPDATE ON memberships FOR EACH ROW
  WHEN (OLD.active IS DISTINCT FROM NEW.active)
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TRIGGER membership_removed
  AFTER DELETE ON memberships FOR EACH ROW
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TRIGGER grant_changed
  AFTER UPDATE OR DELETE ON grants FOR EACH ROW
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TRIGGER role_updated
  AFTER UPDATE ON roles FOR EACH ROW
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TRIGGER role_deleted
  BEFORE DELETE ON roles FOR EACH ROW
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TRIGGER role_assignment_changed
  AFTER DELETE ON role_assignments FOR EACH ROW
  EXECUTE FUNCTION invalidate_identity_sessions();

-- Challenge invalidation triggers
CREATE TRIGGER challenges_changed
  AFTER UPDATE ON users FOR EACH ROW
  WHEN ((OLD.active, OLD.password_hash, OLD.email)
    IS DISTINCT FROM (NEW.active, NEW.password_hash, NEW.email))
  EXECUTE FUNCTION invalidate_identity_challenges();

CREATE TRIGGER otp_policy_changed
  AFTER UPDATE OF otp_enabled ON users FOR EACH ROW
  WHEN (OLD.otp_enabled IS DISTINCT FROM NEW.otp_enabled)
  EXECUTE FUNCTION invalidate_otp_challenges();

-- Permission catalog enforcement
CREATE TRIGGER grant_catalog
  BEFORE INSERT OR UPDATE ON grants FOR EACH ROW
  EXECUTE FUNCTION enforce_permission_catalog();

CREATE TRIGGER role_catalog
  BEFORE INSERT OR UPDATE ON roles FOR EACH ROW
  EXECUTE FUNCTION enforce_permission_catalog();

CREATE TRIGGER service_catalog
  BEFORE INSERT OR UPDATE ON service_accounts FOR EACH ROW
  EXECUTE FUNCTION enforce_permission_catalog();

-- ─── Indexes ─────────────────────────────────────────────────────────
CREATE INDEX sessions_user        ON sessions(environment_id, user_id);
CREATE INDEX memberships_user     ON memberships(environment_id, user_id);
CREATE INDEX environments_project ON environments(project_id);
CREATE INDEX challenge_user       ON identity_challenges(environment_id, user_id, purpose, created_at);
CREATE INDEX audit_environment    ON audit_events(environment_id, id);
CREATE INDEX oauth_request_family ON oauth_requests(environment_id, request_id);
