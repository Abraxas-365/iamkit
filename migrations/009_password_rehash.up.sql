-- A password sign-in replaces a stale hash (an imported format, or bcrypt below
-- the current cost) by a fresh one for the same password. That is not a
-- password change, so it must not end sessions or spend emailed challenges:
-- both triggers skip an update that only changes password_hash while the
-- transaction-local setting iamkit.password_rehash is 'on' (authpg
-- Transaction.RehashPassword sets it for that one statement). Any other
-- change to the row still fires them.
DROP TRIGGER challenges_changed ON users;
CREATE TRIGGER challenges_changed AFTER UPDATE ON users
  FOR EACH ROW WHEN (
    old.active IS DISTINCT FROM new.active
    OR old.email IS DISTINCT FROM new.email
    OR (old.password_hash IS DISTINCT FROM new.password_hash
        AND coalesce(current_setting('iamkit.password_rehash', true), '') <> 'on'))
  EXECUTE FUNCTION invalidate_identity_challenges();

DROP TRIGGER user_changed ON users;
CREATE TRIGGER user_changed AFTER UPDATE ON users
  FOR EACH ROW WHEN (
    old.active IS DISTINCT FROM new.active
    OR old.email IS DISTINCT FROM new.email
    OR (old.password_hash IS DISTINCT FROM new.password_hash
        AND coalesce(current_setting('iamkit.password_rehash', true), '') <> 'on'))
  EXECUTE FUNCTION invalidate_identity_sessions();
