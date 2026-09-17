-- Organization structure describes people, never operator authority.
ALTER TABLE organizations ADD COLUMN active boolean NOT NULL DEFAULT true;
ALTER TABLE organizations ADD COLUMN metadata jsonb NOT NULL DEFAULT '{}';
ALTER TABLE users ADD COLUMN email_verified boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN metadata jsonb NOT NULL DEFAULT '{}';
CREATE TABLE org_units (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL, organization_id uuid NOT NULL,
 parent_id uuid, name text NOT NULL CHECK(length(trim(name))>0), kind text NOT NULL,
 UNIQUE(environment_id,organization_id,id),
 FOREIGN KEY(organization_id,environment_id) REFERENCES organizations(id,environment_id),
 FOREIGN KEY(environment_id,organization_id,parent_id) REFERENCES org_units(environment_id,organization_id,id),
 CHECK(parent_id IS DISTINCT FROM id)
);
CREATE TABLE positions (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL, organization_id uuid NOT NULL,
 name text NOT NULL CHECK(length(trim(name))>0), code text NOT NULL,
 UNIQUE(environment_id,organization_id,id), UNIQUE(organization_id,code),
 FOREIGN KEY(organization_id,environment_id) REFERENCES organizations(id,environment_id)
);
CREATE TABLE position_assignments (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL, organization_id uuid NOT NULL,
 position_id uuid NOT NULL, user_id uuid NOT NULL, org_unit_id uuid,
 FOREIGN KEY(environment_id,organization_id,position_id) REFERENCES positions(environment_id,organization_id,id),
 FOREIGN KEY(environment_id,organization_id,user_id) REFERENCES memberships(environment_id,organization_id,user_id),
 FOREIGN KEY(environment_id,organization_id,org_unit_id) REFERENCES org_units(environment_id,organization_id,id)
);
ALTER TABLE memberships ADD COLUMN org_unit_id uuid;
ALTER TABLE memberships ADD COLUMN manager_id uuid;
ALTER TABLE memberships ADD CONSTRAINT membership_unit FOREIGN KEY(environment_id,organization_id,org_unit_id) REFERENCES org_units(environment_id,organization_id,id);
ALTER TABLE memberships ADD CONSTRAINT membership_manager FOREIGN KEY(environment_id,organization_id,manager_id) REFERENCES memberships(environment_id,organization_id,user_id);
ALTER TABLE memberships ADD CONSTRAINT no_self_manager CHECK(manager_id IS DISTINCT FROM user_id);
CREATE TABLE roles (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL, resource_id uuid NOT NULL,
 name text NOT NULL CHECK(length(trim(name))>0), permissions text[] NOT NULL DEFAULT '{}',
 UNIQUE(environment_id,resource_id,id), UNIQUE(resource_id,name),
 FOREIGN KEY(resource_id,environment_id) REFERENCES resources(id,environment_id)
);
CREATE TABLE role_assignments (
 environment_id uuid NOT NULL, organization_id uuid NOT NULL, user_id uuid NOT NULL,
 resource_id uuid NOT NULL, role_id uuid NOT NULL,
 PRIMARY KEY(organization_id,user_id,role_id),
 FOREIGN KEY(environment_id,organization_id,user_id) REFERENCES memberships(environment_id,organization_id,user_id),
 FOREIGN KEY(environment_id,resource_id,role_id) REFERENCES roles(environment_id,resource_id,id) ON DELETE CASCADE
);
CREATE VIEW effective_grants AS
 SELECT environment_id,organization_id,user_id,resource_id,
 COALESCE(array_agg(DISTINCT permission) FILTER(WHERE permission IS NOT NULL),'{}') AS permissions
 FROM (
  SELECT g.environment_id,g.organization_id,g.user_id,g.resource_id,p.permission
  FROM grants g LEFT JOIN LATERAL unnest(g.permissions) p(permission) ON true
  UNION ALL
  SELECT a.environment_id,a.organization_id,a.user_id,a.resource_id,p.permission
  FROM role_assignments a JOIN roles r ON r.id=a.role_id
  LEFT JOIN LATERAL unnest(r.permissions) p(permission) ON true
 ) access GROUP BY environment_id,organization_id,user_id,resource_id;
-- Revocation is sticky: restoration of a membership/grant never revives a session.
CREATE FUNCTION invalidate_identity_sessions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='users' THEN
  UPDATE sessions SET revoked_at=now() WHERE environment_id=OLD.environment_id AND user_id=OLD.id AND revoked_at IS NULL;
 ELSIF TG_TABLE_NAME='organizations' THEN
  UPDATE sessions SET revoked_at=now() WHERE environment_id=OLD.environment_id AND organization_id=OLD.id AND revoked_at IS NULL;
 ELSIF TG_TABLE_NAME='applications' THEN
  UPDATE sessions SET revoked_at=now() WHERE environment_id=OLD.environment_id AND application_id=OLD.id AND revoked_at IS NULL;
 ELSIF TG_TABLE_NAME='roles' THEN
  UPDATE sessions s SET revoked_at=now() FROM role_assignments a WHERE a.role_id=OLD.id AND s.environment_id=a.environment_id AND s.organization_id=a.organization_id AND s.user_id=a.user_id AND s.resource_id=a.resource_id AND s.revoked_at IS NULL;
 ELSIF TG_TABLE_NAME='memberships' THEN
  UPDATE sessions SET revoked_at=now() WHERE environment_id=OLD.environment_id AND organization_id=OLD.organization_id AND user_id=OLD.user_id AND revoked_at IS NULL;
 ELSE
  UPDATE sessions SET revoked_at=now() WHERE environment_id=OLD.environment_id AND organization_id=OLD.organization_id AND user_id=OLD.user_id AND resource_id=OLD.resource_id AND revoked_at IS NULL;
 END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER user_changed AFTER UPDATE OF active,password_hash,email ON users FOR EACH ROW EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER organization_changed AFTER UPDATE OF active ON organizations FOR EACH ROW EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER application_changed AFTER UPDATE OF active ON applications FOR EACH ROW EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER membership_changed AFTER UPDATE OF active,role OR DELETE ON memberships FOR EACH ROW EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER grant_changed AFTER UPDATE OR DELETE ON grants FOR EACH ROW EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER role_changed BEFORE UPDATE OR DELETE ON roles FOR EACH ROW EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER role_assignment_changed AFTER DELETE ON role_assignments FOR EACH ROW EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TABLE audit_events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, environment_id uuid NOT NULL REFERENCES environments(id),
 actor_id uuid NOT NULL, action text NOT NULL, target_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_environment ON audit_events(environment_id,id);
