-- Groups: named, flat sets of organization members. A group is either managed
-- by operators (connection_id IS NULL) or owned by a SCIM provisioning
-- connection, which then controls its name and members. Roles bound to a
-- group apply to every member through effective_grants; nothing is copied
-- into role_assignments, so direct and group-derived roles stay independent.
CREATE TABLE groups (
  id              uuid        PRIMARY KEY,
  environment_id  uuid        NOT NULL,
  organization_id uuid        NOT NULL,
  name            text        NOT NULL CHECK (length(trim(name)) > 0),
  description     text        NOT NULL DEFAULT '',
  connection_id   uuid,
  external_id     text,
  version         bigint      NOT NULL DEFAULT 0,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, environment_id, organization_id),
  FOREIGN KEY (organization_id, environment_id)
    REFERENCES organizations(id, environment_id),
  FOREIGN KEY (connection_id, environment_id, organization_id)
    REFERENCES provisioning_connections(id, environment_id, organization_id)
);
-- Names are unique among operator groups and within each directory; a
-- directory group may share a name with an operator group.
CREATE UNIQUE INDEX groups_manual_name ON groups(organization_id, lower(name)) WHERE connection_id IS NULL;
CREATE UNIQUE INDEX groups_connection_name ON groups(connection_id, lower(name)) WHERE connection_id IS NOT NULL;
CREATE UNIQUE INDEX groups_connection_external ON groups(connection_id, external_id) WHERE external_id IS NOT NULL;

CREATE TABLE group_members (
  group_id        uuid        NOT NULL,
  environment_id  uuid        NOT NULL,
  organization_id uuid        NOT NULL,
  user_id         uuid        NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, user_id),
  FOREIGN KEY (group_id, environment_id, organization_id)
    REFERENCES groups(id, environment_id, organization_id) ON DELETE CASCADE,
  FOREIGN KEY (environment_id, organization_id, user_id)
    REFERENCES memberships(environment_id, organization_id, user_id) ON DELETE CASCADE
);
CREATE INDEX group_members_user ON group_members(organization_id, user_id);

CREATE TABLE group_role_assignments (
  group_id        uuid        NOT NULL,
  environment_id  uuid        NOT NULL,
  organization_id uuid        NOT NULL,
  resource_id     uuid        NOT NULL,
  role_id         uuid        NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, role_id),
  FOREIGN KEY (group_id, environment_id, organization_id)
    REFERENCES groups(id, environment_id, organization_id) ON DELETE CASCADE,
  FOREIGN KEY (environment_id, resource_id, role_id)
    REFERENCES roles(environment_id, resource_id, id) ON DELETE CASCADE
);
CREATE INDEX group_role_assignments_role ON group_role_assignments(role_id);

-- Effective access = direct grants ∪ direct roles ∪ roles of the user's groups.
CREATE OR REPLACE VIEW effective_grants AS
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
    UNION ALL
    SELECT gm.environment_id, gm.organization_id, gm.user_id, ga.resource_id, p.permission
      FROM group_members gm
      JOIN group_role_assignments ga ON ga.group_id = gm.group_id
      JOIN roles r ON r.id = ga.role_id
      LEFT JOIN LATERAL unnest(r.permissions) p(permission) ON true
  ) access
  GROUP BY environment_id, organization_id, user_id, resource_id;
