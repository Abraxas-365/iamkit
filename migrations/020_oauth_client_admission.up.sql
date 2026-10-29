-- MCP authorization, phase (b) review (H1, H2, L4). Additive to 019.

-- H2: an approval is tied to the metadata that was approved. A manual
-- approval returns to pending when the redirect URIs, jwks_uri or token
-- endpoint authentication of the document change; admission_source says who
-- approved ('' = unknown, treated as manual) and approved_metadata_hash is
-- oauth.MetadataHash of what was approved ('' = the row's own fields).
-- discovered_at ages pending clients nobody used (client_pending_prune).
ALTER TABLE oauth_clients
    ADD COLUMN admission_source text DEFAULT ''::text NOT NULL,
    ADD COLUMN approved_metadata_hash text DEFAULT ''::text NOT NULL,
    ADD COLUMN discovered_at timestamp with time zone DEFAULT now() NOT NULL,
    ADD CONSTRAINT oauth_clients_admission_source_check CHECK ((admission_source = ANY (ARRAY[''::text, 'manual'::text, 'allowlist'::text, 'open'::text, 'preset'::text])));

CREATE INDEX oauth_clients_pending_prune ON oauth_clients USING btree (discovered_at)
    WHERE ((source = 'cimd'::text) AND (admission = 'pending'::text) AND (last_used_at IS NULL));

-- H1: an anonymous authorization of a client nobody approved persists no
-- oauth_clients row. Its ticket carries the client_id URL and the protected
-- resource instead; the row is written after the user signs in.
ALTER TABLE oauth_authorizations
    ALTER COLUMN client_id DROP NOT NULL,
    ADD COLUMN external_id text,
    ADD COLUMN protected_resource_id uuid,
    ADD CONSTRAINT oauth_authorizations_client_check CHECK (((client_id IS NOT NULL AND external_id IS NULL AND protected_resource_id IS NULL)
        OR (client_id IS NULL AND external_id IS NOT NULL AND protected_resource_id IS NOT NULL))),
    ADD CONSTRAINT oauth_authorizations_protected_resource_fkey FOREIGN KEY (protected_resource_id, environment_id) REFERENCES protected_resources(id, environment_id) ON DELETE CASCADE;

-- Bookkeeping of external clients is not change history: the usage and fetch
-- times and the approved hash change without an operator or a document
-- change worth a diff (only record_changes' hidden list differs from 001).
CREATE OR REPLACE FUNCTION record_changes() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  hidden text[] := ARRAY['id', 'environment_id', 'created_at', 'updated_at', 'version',
    'password_hash', 'secret_hash', 'failed_logins', 'last_signed_in_at', 'password_changed_at', 'jwks',
    'last_used_at', 'metadata_fetched_at', 'discovered_at', 'approved_metadata_hash'];
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
