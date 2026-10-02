-- 047: Change history — before/after values on update events.
--
-- An UPDATE of a tracked table records which columns changed, as
-- {"column": [old, new]}, in the transaction-local setting iamkit.changes
-- (a jsonb object keyed by "<table>:<id>"; several updates of one row in a
-- transaction keep the first old and the last new value). The next event
-- written in that transaction about the same subject takes the entry as
-- data.changes. Writers need no change: eventpg.Audit runs after the
-- UPDATE in the same transaction. JSON object columns (metadata, profile)
-- are compared per key ("metadata.plan"). Secrets, hashes and
-- bookkeeping columns are never recorded. A transaction records at most
-- 100 rows (iamkit.changes_n), so bulk updates such as ON DELETE SET NULL
-- cascades stay cheap; later rows' events carry no changes.

CREATE FUNCTION record_changes() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  hidden text[] := ARRAY['id', 'environment_id', 'created_at', 'updated_at', 'version',
    'password_hash', 'secret_hash', 'failed_logins', 'last_signed_in_at', 'password_changed_at', 'jwks'];
  old_row jsonb := to_jsonb(OLD);
  new_row jsonb := to_jsonb(NEW);
  diff jsonb := '{}';
  col text;
  sub text;
  a jsonb;
  b jsonb;
  key text := TG_TABLE_NAME || ':' || NEW.id::text;
  pending jsonb;
  prior jsonb;
  merged jsonb := '{}';
BEGIN
  IF coalesce(nullif(current_setting('iamkit.changes_n', true), ''), '0')::int >= 100 THEN
    RETURN NULL;
  END IF;
  FOR col IN SELECT jsonb_object_keys(new_row) LOOP
    CONTINUE WHEN col = ANY(hidden);
    a := old_row -> col;
    b := new_row -> col;
    CONTINUE WHEN a IS NOT DISTINCT FROM b;
    IF jsonb_typeof(a) = 'object' AND jsonb_typeof(b) = 'object' THEN
      FOR sub IN SELECT k FROM jsonb_object_keys(a) k UNION SELECT k FROM jsonb_object_keys(b) k LOOP
        IF (a -> sub) IS DISTINCT FROM (b -> sub) THEN
          diff := diff || jsonb_build_object(col || '.' || sub, jsonb_build_array(a -> sub, b -> sub));
        END IF;
      END LOOP;
    ELSE
      diff := diff || jsonb_build_object(col, jsonb_build_array(a, b));
    END IF;
  END LOOP;
  IF diff = '{}' THEN
    RETURN NULL;
  END IF;
  pending := coalesce(nullif(current_setting('iamkit.changes', true), ''), '{}')::jsonb;
  prior := pending -> key;
  IF prior IS NOT NULL THEN
    -- Merge: the first old value, the latest new one; drop no-ops.
    FOR col IN SELECT k FROM jsonb_object_keys(prior) k UNION SELECT k FROM jsonb_object_keys(diff) k LOOP
      a := coalesce(prior -> col -> 0, diff -> col -> 0);
      b := coalesce(diff -> col -> 1, prior -> col -> 1);
      IF a IS DISTINCT FROM b THEN
        merged := merged || jsonb_build_object(col, jsonb_build_array(a, b));
      END IF;
    END LOOP;
    diff := merged;
  END IF;
  IF prior IS NULL THEN
    PERFORM set_config('iamkit.changes_n', (coalesce(nullif(current_setting('iamkit.changes_n', true), ''), '0')::int + 1)::text, true);
  END IF;
  PERFORM set_config('iamkit.changes', (pending || jsonb_build_object(key, diff))::text, true);
  RETURN NULL;
END $$;

CREATE TRIGGER record_changes AFTER UPDATE ON users FOR EACH ROW EXECUTE FUNCTION record_changes();
CREATE TRIGGER record_changes AFTER UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION record_changes();
CREATE TRIGGER record_changes AFTER UPDATE ON applications FOR EACH ROW EXECUTE FUNCTION record_changes();
CREATE TRIGGER record_changes AFTER UPDATE ON oauth_clients FOR EACH ROW EXECUTE FUNCTION record_changes();
CREATE TRIGGER record_changes AFTER UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION record_changes();
CREATE TRIGGER record_changes AFTER UPDATE ON resources FOR EACH ROW EXECUTE FUNCTION record_changes();

-- event_changes moves the pending changes of the event's subject into
-- its data (once: the entry is consumed).
CREATE FUNCTION event_changes() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  tbl text;
  key text;
  pending jsonb;
BEGIN
  IF NEW.subject_id = '' OR NEW.data ? 'changes' THEN
    RETURN NEW;
  END IF;
  tbl := CASE NEW.subject_kind
    WHEN 'user' THEN 'users' WHEN 'organization' THEN 'organizations'
    WHEN 'application' THEN 'applications' WHEN 'oauth_client' THEN 'oauth_clients'
    WHEN 'role' THEN 'roles' WHEN 'resource' THEN 'resources' END;
  IF tbl IS NULL THEN
    RETURN NEW;
  END IF;
  pending := nullif(current_setting('iamkit.changes', true), '')::jsonb;
  key := tbl || ':' || NEW.subject_id;
  IF pending IS NULL OR NOT pending ? key THEN
    RETURN NEW;
  END IF;
  NEW.data := NEW.data || jsonb_build_object('changes', pending -> key);
  PERFORM set_config('iamkit.changes', (pending - key)::text, true);
  RETURN NEW;
END $$;
CREATE TRIGGER event_changes BEFORE INSERT ON events
  FOR EACH ROW EXECUTE FUNCTION event_changes();

