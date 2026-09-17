-- IAMKit fresh-database schema. Incompatible with the legacy org-owned identity model.
-- No default identities or credentials are installed.
CREATE TABLE workspaces (
 id uuid PRIMARY KEY, name text NOT NULL CHECK (length(trim(name)) > 0), created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE operators (
 id uuid PRIMARY KEY, email text NOT NULL UNIQUE CHECK (email = lower(trim(email))), created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE workspace_members (
 workspace_id uuid NOT NULL REFERENCES workspaces(id), operator_id uuid NOT NULL REFERENCES operators(id),
 role text NOT NULL CHECK (role IN ('owner','admin','viewer')), active boolean NOT NULL DEFAULT true, PRIMARY KEY(workspace_id,operator_id)
);
CREATE TABLE management_keys (
 id uuid PRIMARY KEY, workspace_id uuid NOT NULL, operator_id uuid NOT NULL,
 secret_hash bytea NOT NULL UNIQUE, expires_at timestamptz NOT NULL, revoked_at timestamptz,
 FOREIGN KEY(workspace_id,operator_id) REFERENCES workspace_members(workspace_id,operator_id)
);
CREATE TABLE projects (
 id uuid PRIMARY KEY, workspace_id uuid NOT NULL REFERENCES workspaces(id), name text NOT NULL,
 UNIQUE(id,workspace_id)
);
CREATE TABLE environments (
 id uuid PRIMARY KEY, project_id uuid NOT NULL REFERENCES projects(id), name text NOT NULL,
 UNIQUE(project_id,name)
);
CREATE TABLE users (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL REFERENCES environments(id),
 email text NOT NULL CHECK (email = lower(trim(email))), name text NOT NULL,
 password_hash text NOT NULL, active boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(id,environment_id), UNIQUE(environment_id,email)
);
CREATE TABLE organizations (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL REFERENCES environments(id), name text NOT NULL,
 UNIQUE(id,environment_id)
);
CREATE TABLE memberships (
 environment_id uuid NOT NULL, organization_id uuid NOT NULL, user_id uuid NOT NULL,
 role text NOT NULL CHECK (role IN ('owner','admin','member')), active boolean NOT NULL DEFAULT true,
 PRIMARY KEY(organization_id,user_id), UNIQUE(environment_id,organization_id,user_id),
 FOREIGN KEY(organization_id,environment_id) REFERENCES organizations(id,environment_id),
 FOREIGN KEY(user_id,environment_id) REFERENCES users(id,environment_id)
);
-- Clients and resources are deliberately separate: client identity is not an API audience.
CREATE TABLE applications (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL REFERENCES environments(id), name text NOT NULL,
 redirect_uris text[] NOT NULL DEFAULT '{}', active boolean NOT NULL DEFAULT true,
 UNIQUE(id,environment_id)
);
CREATE TABLE resources (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL REFERENCES environments(id), name text NOT NULL,
 audience text NOT NULL CHECK (length(trim(audience)) > 0), permissions text[] NOT NULL DEFAULT '{}',
 UNIQUE(id,environment_id), UNIQUE(environment_id,audience)
);
CREATE TABLE application_resources (
 environment_id uuid NOT NULL, application_id uuid NOT NULL, resource_id uuid NOT NULL,
 PRIMARY KEY(application_id,resource_id), UNIQUE(environment_id,application_id,resource_id),
 FOREIGN KEY(application_id,environment_id) REFERENCES applications(id,environment_id),
 FOREIGN KEY(resource_id,environment_id) REFERENCES resources(id,environment_id)
);
CREATE TABLE grants (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL, organization_id uuid NOT NULL, user_id uuid NOT NULL,
 resource_id uuid NOT NULL, permissions text[] NOT NULL DEFAULT '{}',
 UNIQUE(organization_id,user_id,resource_id),
 FOREIGN KEY(environment_id,organization_id,user_id) REFERENCES memberships(environment_id,organization_id,user_id),
 FOREIGN KEY(resource_id,environment_id) REFERENCES resources(id,environment_id)
);
CREATE TABLE sessions (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL, organization_id uuid NOT NULL, user_id uuid NOT NULL,
 application_id uuid NOT NULL, resource_id uuid NOT NULL,
 expires_at timestamptz NOT NULL, revoked_at timestamptz,
 FOREIGN KEY(environment_id,organization_id,user_id) REFERENCES memberships(environment_id,organization_id,user_id),
 FOREIGN KEY(environment_id,application_id,resource_id) REFERENCES application_resources(environment_id,application_id,resource_id)
);
-- Operator-provisioned, app/resource-bound machine identities. Never management credentials.
CREATE TABLE service_accounts (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL, application_id uuid NOT NULL, resource_id uuid NOT NULL,
 name text NOT NULL, permissions text[] NOT NULL DEFAULT '{}', secret_hash bytea NOT NULL UNIQUE,
 expires_at timestamptz NOT NULL, revoked_at timestamptz,
 FOREIGN KEY(environment_id,application_id,resource_id) REFERENCES application_resources(environment_id,application_id,resource_id)
);
CREATE INDEX sessions_user ON sessions(environment_id,user_id);
CREATE INDEX memberships_user ON memberships(environment_id,user_id);
CREATE INDEX environments_project ON environments(project_id);
