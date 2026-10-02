-- Organization-scoped administration (B1).

-- 1. Org-bound permissions on every environment's IAM resource.
UPDATE resources SET permissions = permissions || ARRAY(
    SELECT p FROM unnest(ARRAY[
        'iam:org:read', 'iam:org:settings:write',
        'iam:org:members:read', 'iam:org:members:write', 'iam:org:users:write',
        'iam:org:roles:read', 'iam:org:roles:assign',
        'iam:org:invitations:write', 'iam:org:domains:write',
        'iam:org:sso:write', 'iam:org:audit:read']) p
    WHERE NOT p = ANY(permissions))
WHERE prefix = 'iam';

-- 2. Built-in roles of the IAM resource: fixed permissions, never edited
-- or deleted. system_role names them independently of their display name.
ALTER TABLE roles ADD COLUMN system_role text
    CHECK (system_role IN ('org_owner', 'org_viewer', 'org_user_manager', 'org_settings_manager'));
CREATE UNIQUE INDEX roles_resource_system_role ON roles(resource_id, system_role) WHERE system_role IS NOT NULL;

-- Custom roles that already use a built-in name keep working under a new one.
UPDATE roles r SET name = r.name || ' (custom)'
FROM resources res
WHERE res.id = r.resource_id AND res.prefix = 'iam'
  AND r.name IN ('Organization owner', 'Organization viewer', 'User manager', 'Settings manager');

INSERT INTO roles(id, environment_id, resource_id, name, permissions, system_role)
SELECT gen_random_uuid(), res.environment_id, res.id, s.name, s.permissions, s.key
FROM resources res
CROSS JOIN (VALUES
    ('org_owner', 'Organization owner', ARRAY[
        'iam:org:read', 'iam:org:settings:write',
        'iam:org:members:read', 'iam:org:members:write', 'iam:org:users:write',
        'iam:org:roles:read', 'iam:org:roles:assign',
        'iam:org:invitations:write', 'iam:org:domains:write',
        'iam:org:sso:write', 'iam:org:audit:read']),
    ('org_viewer', 'Organization viewer', ARRAY['iam:org:read', 'iam:org:members:read', 'iam:org:roles:read']),
    ('org_user_manager', 'User manager', ARRAY[
        'iam:org:read', 'iam:org:members:read', 'iam:org:members:write', 'iam:org:users:write',
        'iam:org:roles:read', 'iam:org:roles:assign', 'iam:org:invitations:write']),
    ('org_settings_manager', 'Settings manager', ARRAY[
        'iam:org:read', 'iam:org:settings:write', 'iam:org:domains:write', 'iam:org:sso:write'])
) AS s(key, name, permissions)
WHERE res.prefix = 'iam';

-- 3. Home organization: organization administrators edit a user's record
-- only when the user belongs to their organization. Existing users with
-- exactly one membership are homed there.
ALTER TABLE users ADD COLUMN home_organization_id uuid;
ALTER TABLE users ADD CONSTRAINT users_home_organization
    FOREIGN KEY (home_organization_id, environment_id) REFERENCES organizations(id, environment_id);

UPDATE users u SET home_organization_id = m.organization_id
FROM (SELECT environment_id, user_id, min(organization_id::text)::uuid AS organization_id
      FROM memberships GROUP BY environment_id, user_id HAVING count(*) = 1) m
WHERE m.environment_id = u.environment_id AND m.user_id = u.id;

-- 4. Audit events know who acted (operator, end user, service account)
-- and which organization they concern, so organization administrators
-- read their organization's events. A trigger fills both, so every
-- existing writer keeps inserting the same four columns.
ALTER TABLE audit_events
    ADD COLUMN actor_kind text NOT NULL DEFAULT 'operator'
        CHECK (actor_kind IN ('operator', 'user', 'service_account', 'system')),
    ADD COLUMN organization_id uuid;

CREATE FUNCTION audit_event_context() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE id = NEW.actor_id AND environment_id = NEW.environment_id) THEN
        NEW.actor_kind := 'user';
    ELSIF EXISTS (SELECT 1 FROM service_accounts WHERE id = NEW.actor_id AND environment_id = NEW.environment_id) THEN
        NEW.actor_kind := 'service_account';
    END IF;
    IF NEW.organization_id IS NULL THEN
        NEW.organization_id := substring(NEW.target_id FROM '/organizations/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')::uuid;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER audit_event_context BEFORE INSERT ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_event_context();

UPDATE audit_events e SET actor_kind = 'user'
WHERE EXISTS (SELECT 1 FROM users WHERE id = e.actor_id AND environment_id = e.environment_id);
UPDATE audit_events e SET actor_kind = 'service_account'
WHERE EXISTS (SELECT 1 FROM service_accounts WHERE id = e.actor_id AND environment_id = e.environment_id);
UPDATE audit_events SET organization_id = substring(target_id FROM '/organizations/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')::uuid
WHERE target_id ~ '/organizations/[0-9a-fA-F-]{36}';

CREATE INDEX audit_events_organization ON audit_events(environment_id, organization_id, id DESC) WHERE organization_id IS NOT NULL;
