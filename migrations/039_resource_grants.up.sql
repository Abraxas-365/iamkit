-- Resource grants (B2): a resource may belong to an organization (the vendor
-- that ships it) and be granted to other organizations, whose own
-- administrators then assign its roles. require_grant (opt-in, default off)
-- also limits token access to the owner and granted organizations.

ALTER TABLE resources
    ADD COLUMN owner_organization_id uuid,
    ADD COLUMN require_grant boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT resources_owner_organization
        FOREIGN KEY (owner_organization_id, environment_id) REFERENCES organizations(id, environment_id),
    -- The IAM resource is governed by organization administration (038).
    ADD CONSTRAINT resources_iam_unowned
        CHECK (prefix <> 'iam' OR (owner_organization_id IS NULL AND NOT require_grant));

-- role_ids NULL grants every role of the resource, current and future.
CREATE TABLE resource_grants (
    id              uuid        PRIMARY KEY,
    environment_id  uuid        NOT NULL,
    resource_id     uuid        NOT NULL,
    organization_id uuid        NOT NULL,
    role_ids        uuid[],
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (resource_id, organization_id),
    FOREIGN KEY (resource_id, environment_id) REFERENCES resources(id, environment_id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX resource_grants_organization ON resource_grants(organization_id);

-- Effective access keeps its shape; for resources with require_grant it
-- counts only the owner organization and granted organizations (and, for
-- role-derived permissions, only granted roles). Without require_grant the
-- output is the same as before.
CREATE OR REPLACE VIEW effective_grants AS
  SELECT access.environment_id, access.organization_id, access.user_id, access.resource_id,
    COALESCE(array_agg(DISTINCT access.permission)
      FILTER (WHERE access.permission IS NOT NULL), '{}') AS permissions
  FROM (
    SELECT g.environment_id, g.organization_id, g.user_id, g.resource_id, NULL::uuid AS role_id, p.permission
      FROM grants g LEFT JOIN LATERAL unnest(g.permissions) p(permission) ON true
    UNION ALL
    SELECT a.environment_id, a.organization_id, a.user_id, a.resource_id, a.role_id, p.permission
      FROM role_assignments a JOIN roles r ON r.id = a.role_id
      LEFT JOIN LATERAL unnest(r.permissions) p(permission) ON true
    UNION ALL
    SELECT gm.environment_id, gm.organization_id, gm.user_id, ga.resource_id, ga.role_id, p.permission
      FROM group_members gm
      JOIN group_role_assignments ga ON ga.group_id = gm.group_id
      JOIN roles r ON r.id = ga.role_id
      LEFT JOIN LATERAL unnest(r.permissions) p(permission) ON true
  ) access
  JOIN resources res ON res.id = access.resource_id
  WHERE NOT res.require_grant
     OR res.owner_organization_id = access.organization_id
     OR EXISTS (SELECT 1 FROM resource_grants rg
                WHERE rg.resource_id = access.resource_id AND rg.organization_id = access.organization_id
                  AND (access.role_id IS NULL OR rg.role_ids IS NULL OR access.role_id = ANY(rg.role_ids)))
  GROUP BY access.environment_id, access.organization_id, access.user_id, access.resource_id;

-- Organization administrators of the owner organization manage its
-- resources' grants.
UPDATE resources SET permissions = permissions || ARRAY(
    SELECT p FROM unnest(ARRAY['iam:org:resources:read', 'iam:org:resources:write']) p
    WHERE NOT p = ANY(permissions))
WHERE prefix = 'iam';

ALTER TABLE roles DROP CONSTRAINT roles_system_role_check;
ALTER TABLE roles ADD CONSTRAINT roles_system_role_check
    CHECK (system_role IN ('org_owner', 'org_viewer', 'org_user_manager', 'org_settings_manager', 'org_resource_manager'));

UPDATE roles SET permissions = permissions || ARRAY(
    SELECT p FROM unnest(ARRAY['iam:org:resources:read', 'iam:org:resources:write']) p
    WHERE NOT p = ANY(permissions))
WHERE system_role = 'org_owner';

UPDATE roles r SET name = r.name || ' (custom)'
FROM resources res
WHERE res.id = r.resource_id AND res.prefix = 'iam' AND r.system_role IS NULL AND r.name = 'Resource manager';

INSERT INTO roles(id, environment_id, resource_id, name, permissions, system_role)
SELECT gen_random_uuid(), res.environment_id, res.id, 'Resource manager',
       ARRAY['iam:org:read', 'iam:org:resources:read', 'iam:org:resources:write'], 'org_resource_manager'
FROM resources res
WHERE res.prefix = 'iam'
  AND NOT EXISTS (SELECT 1 FROM roles r WHERE r.resource_id = res.id AND r.system_role = 'org_resource_manager');
