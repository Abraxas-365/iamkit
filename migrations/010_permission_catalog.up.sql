-- AFTER UPDATE must not replace NEW with OLD. Delete revocation runs before
-- assignment cascades, while the affected users are still discoverable.
DROP TRIGGER role_changed ON roles;
CREATE TRIGGER role_updated AFTER UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER role_deleted BEFORE DELETE ON roles FOR EACH ROW EXECUTE FUNCTION invalidate_identity_sessions();

-- Serialize every permission writer with catalog updates, including direct SQL.
CREATE FUNCTION enforce_permission_catalog() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE catalog text[];
BEGIN
 SELECT permissions INTO catalog FROM resources WHERE id=NEW.resource_id AND environment_id=NEW.environment_id FOR SHARE;
 IF catalog IS NULL OR NOT NEW.permissions <@ catalog THEN
  RAISE EXCEPTION 'permissions outside resource catalog' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER grant_catalog BEFORE INSERT OR UPDATE ON grants FOR EACH ROW EXECUTE FUNCTION enforce_permission_catalog();
CREATE TRIGGER role_catalog BEFORE INSERT OR UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION enforce_permission_catalog();
CREATE TRIGGER service_catalog BEFORE INSERT OR UPDATE ON service_accounts FOR EACH ROW EXECUTE FUNCTION enforce_permission_catalog();
