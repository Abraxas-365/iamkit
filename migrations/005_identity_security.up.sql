-- Preserve immutable earlier migrations; only actual security changes revoke.
DROP TRIGGER user_changed ON users;
DROP TRIGGER organization_changed ON organizations;
DROP TRIGGER application_changed ON applications;
DROP TRIGGER membership_changed ON memberships;
CREATE TRIGGER user_changed AFTER UPDATE ON users FOR EACH ROW WHEN ((OLD.active,OLD.password_hash,OLD.email) IS DISTINCT FROM (NEW.active,NEW.password_hash,NEW.email)) EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER organization_changed AFTER UPDATE ON organizations FOR EACH ROW WHEN (OLD.active IS DISTINCT FROM NEW.active) EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER application_changed AFTER UPDATE ON applications FOR EACH ROW WHEN (OLD.active IS DISTINCT FROM NEW.active) EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER membership_changed AFTER UPDATE ON memberships FOR EACH ROW WHEN ((OLD.active,OLD.role) IS DISTINCT FROM (NEW.active,NEW.role)) EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER membership_removed AFTER DELETE ON memberships FOR EACH ROW EXECUTE FUNCTION invalidate_identity_sessions();
CREATE FUNCTION invalidate_identity_challenges() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE identity_challenges SET consumed_at=now() WHERE environment_id=OLD.environment_id AND user_id=OLD.id AND consumed_at IS NULL;
 RETURN NEW;
END $$;
CREATE TRIGGER challenges_changed AFTER UPDATE ON users FOR EACH ROW WHEN ((OLD.active,OLD.password_hash,OLD.email) IS DISTINCT FROM (NEW.active,NEW.password_hash,NEW.email)) EXECUTE FUNCTION invalidate_identity_challenges();
CREATE TABLE provisioning_connections (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL, organization_id uuid NOT NULL, name text NOT NULL,
 UNIQUE(id,environment_id,organization_id), UNIQUE(id,environment_id),
 FOREIGN KEY(organization_id,environment_id) REFERENCES organizations(id,environment_id)
);
INSERT INTO provisioning_connections(id,environment_id,organization_id,name) SELECT id,environment_id,organization_id,name FROM provisioning_credentials;
ALTER TABLE provisioning_credentials ADD COLUMN connection_id uuid;
UPDATE provisioning_credentials SET connection_id=id;
ALTER TABLE provisioning_credentials ALTER COLUMN connection_id SET NOT NULL;
ALTER TABLE provisioning_credentials ADD CONSTRAINT provisioning_connection FOREIGN KEY(connection_id,environment_id,organization_id) REFERENCES provisioning_connections(id,environment_id,organization_id);
ALTER TABLE provisioned_identities RENAME COLUMN credential_id TO connection_id;
ALTER TABLE provisioned_identities DROP CONSTRAINT provisioned_identities_credential_id_environment_id_fkey;
ALTER TABLE provisioned_identities ADD CONSTRAINT provisioned_connection FOREIGN KEY(connection_id,environment_id) REFERENCES provisioning_connections(id,environment_id);
ALTER TABLE memberships ADD COLUMN display_name text;
