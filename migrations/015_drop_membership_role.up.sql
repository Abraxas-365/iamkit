-- Drop the hardcoded membership role (owner/admin/member). Org governance is
-- now expressed through ordinary grants/roles on the system IAM resource
-- (e.g. iam:members:write), not a fixed three-value enum on the membership
-- row itself. Membership becomes a pure "user belongs to org" relationship.
--
-- The invalidate_identity_sessions() function body never referenced the role
-- column directly; only the membership_changed trigger's WHEN clause did
-- (see 005_identity_security.up.sql). Recreate that trigger without it.
DROP TRIGGER IF EXISTS membership_changed ON memberships;
CREATE TRIGGER membership_changed AFTER UPDATE ON memberships FOR EACH ROW WHEN (OLD.active IS DISTINCT FROM NEW.active) EXECUTE FUNCTION invalidate_identity_sessions();

ALTER TABLE memberships DROP COLUMN role;
