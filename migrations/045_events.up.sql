-- 045: Semantic events (transactional outbox).
--
-- Every audited change also writes one row here in the same transaction,
-- with a semantic type from the catalog (user.created, role.updated, …)
-- instead of the HTTP method and path audit_events keeps for the console.
-- Sessions add session.created / session.revoked through triggers, so every
-- way a session starts or ends is covered. Rows are append-only; the
-- worker prunes them after IAMKIT_EVENT_RETENTION. Webhook subscriptions
-- (046) read this table by id.
CREATE TABLE events (
  id              bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  environment_id  uuid        NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  type            text        NOT NULL CHECK (type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
  actor_kind      text        NOT NULL CHECK (actor_kind IN ('operator', 'user', 'service_account', 'directory', 'system')),
  actor_id        text        NOT NULL DEFAULT '',
  subject_kind    text        NOT NULL DEFAULT '',
  subject_id      text        NOT NULL DEFAULT '',
  organization_id uuid,
  data            jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(data) = 'object'),
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX events_environment ON events (environment_id, id);
CREATE INDEX events_type ON events (environment_id, type, id);
CREATE INDEX events_subject ON events (environment_id, subject_id, id) WHERE subject_id <> '';
CREATE INDEX events_created ON events (created_at);

-- Writers may leave actor_kind NULL: it is resolved like audit_events'
-- (migration 038) — no actor is the system, else a user, service
-- account or SCIM credential (directory) of the environment, else an
-- operator.
CREATE FUNCTION event_actor() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.actor_kind IS NULL THEN
    IF NEW.actor_id = '' THEN
      NEW.actor_kind := 'system';
    ELSIF NEW.actor_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND EXISTS (SELECT 1 FROM users WHERE id = NEW.actor_id::uuid AND environment_id = NEW.environment_id) THEN
      NEW.actor_kind := 'user';
    ELSIF NEW.actor_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND EXISTS (SELECT 1 FROM service_accounts WHERE id = NEW.actor_id::uuid AND environment_id = NEW.environment_id) THEN
      NEW.actor_kind := 'service_account';
    ELSIF NEW.actor_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND EXISTS (SELECT 1 FROM provisioning_credentials WHERE id = NEW.actor_id::uuid AND environment_id = NEW.environment_id) THEN
      NEW.actor_kind := 'directory';
    ELSE
      NEW.actor_kind := 'operator';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER event_actor BEFORE INSERT ON events
  FOR EACH ROW EXECUTE FUNCTION event_actor();

-- Sessions: created and ended (revoked or deleted), whatever path did it.
CREATE FUNCTION session_event() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  s sessions%ROWTYPE;
  kind text := 'user';
  actor text;
  t text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    s := NEW;
    t := 'session.created';
  ELSIF TG_OP = 'DELETE' THEN
    s := OLD;
    IF OLD.revoked_at IS NOT NULL OR OLD.expires_at <= now() THEN
      RETURN NULL;
    END IF;
    t := 'session.revoked';
  ELSE
    s := NEW;
    t := 'session.revoked';
  END IF;
  actor := s.user_id::text;
  IF s.actor_id IS NOT NULL THEN
    kind := 'operator';
    actor := s.actor_id::text;
  ELSIF s.actor_account_id IS NOT NULL THEN
    kind := 'service_account';
    actor := s.actor_account_id::text;
  ELSIF t = 'session.revoked' THEN
    kind := 'system';
    actor := '';
  END IF;
  INSERT INTO events (environment_id, type, actor_kind, actor_id, subject_kind, subject_id, organization_id, data)
  SELECT s.environment_id, t, kind, actor, 'session', s.id::text, s.organization_id,
    jsonb_strip_nulls(jsonb_build_object(
      'user_id', s.user_id, 'organization_id', s.organization_id,
      'application_id', s.application_id, 'resource_id', s.resource_id,
      'oauth_client_id', s.oauth_client_id, 'amr', to_jsonb(s.amr),
      'impersonated', s.actor_id IS NOT NULL OR s.actor_account_id IS NOT NULL,
      'parent_session_id', s.parent_session_id,
      'expires_at', CASE WHEN t = 'session.created' THEN s.expires_at END))
  WHERE EXISTS (SELECT 1 FROM environments WHERE id = s.environment_id);
  RETURN NULL;
END $$;

CREATE TRIGGER session_created_event
  AFTER INSERT ON sessions FOR EACH ROW
  EXECUTE FUNCTION session_event();
CREATE TRIGGER session_revoked_event
  AFTER UPDATE OF revoked_at ON sessions FOR EACH ROW
  WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
  EXECUTE FUNCTION session_event();
CREATE TRIGGER session_deleted_event
  AFTER DELETE ON sessions FOR EACH ROW
  EXECUTE FUNCTION session_event();

-- iam:events:read opens the /api/v1 event log to service accounts.
UPDATE resources SET permissions = permissions || ARRAY['iam:events:read']
WHERE prefix = 'iam' AND NOT 'iam:events:read' = ANY(permissions);
