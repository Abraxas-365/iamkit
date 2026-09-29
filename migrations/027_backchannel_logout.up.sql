-- 027: OpenID Connect Back-Channel Logout 1.0.
--
-- A client with a backchannel_logout_uri receives a signed logout token
-- (server to server) when a session it was authorized for ends: sign-out,
-- revocation, suspension, permission changes or deletion. Existing clients
-- have no URI and receive nothing.
ALTER TABLE oauth_clients
  ADD COLUMN backchannel_logout_uri text NOT NULL DEFAULT '',
  ADD COLUMN backchannel_logout_session_required boolean NOT NULL DEFAULT false;

-- The outbox the dispatcher drains. A row is claimed by pushing
-- next_attempt_at forward (a lease), so several replicas never send the
-- same notification at once and a crashed sender's rows come back.
CREATE TABLE logout_notifications (
  id              bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  environment_id  uuid        NOT NULL,
  client_id       uuid        NOT NULL,
  session_id      uuid        NOT NULL,
  subject         uuid        NOT NULL,
  attempts        integer     NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  delivered_at    timestamptz,
  failed_at       timestamptz,
  last_error      text        NOT NULL DEFAULT '',
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX logout_notifications_due ON logout_notifications (next_attempt_at)
  WHERE delivered_at IS NULL AND failed_at IS NULL;

-- Every way a live session ends passes through here: revoked_at being set
-- (logout, revocation, the invalidate_identity_sessions triggers) or the
-- row being deleted (permanent user deletion).
CREATE FUNCTION queue_logout_notification() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  s sessions%ROWTYPE;
BEGIN
  IF TG_OP = 'DELETE' THEN
    s := OLD;
  ELSE
    s := NEW;
  END IF;
  IF s.oauth_client_id IS NULL OR OLD.revoked_at IS NOT NULL OR s.expires_at <= now() THEN
    RETURN NULL;
  END IF;
  INSERT INTO logout_notifications (environment_id, client_id, session_id, subject)
    SELECT s.environment_id, c.id, s.id, s.user_id FROM oauth_clients c
    WHERE c.id = s.oauth_client_id AND c.environment_id = s.environment_id
      AND c.active AND c.backchannel_logout_uri <> '';
  RETURN NULL;
END $$;

CREATE TRIGGER session_ended
  AFTER UPDATE OF revoked_at ON sessions FOR EACH ROW
  WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
  EXECUTE FUNCTION queue_logout_notification();

CREATE TRIGGER session_deleted
  AFTER DELETE ON sessions FOR EACH ROW
  EXECUTE FUNCTION queue_logout_notification();
