-- Where a session was opened from: the client address and User-Agent of the
-- request that created it (NULL when the session was not created by an HTTP
-- request, or before this column existed). Users see them in
-- /identity/v1/me/sessions, operators in the session inventory.
ALTER TABLE sessions
    ADD COLUMN ip_address inet,
    ADD COLUMN user_agent text,
    ADD CONSTRAINT sessions_user_agent_length CHECK (user_agent IS NULL OR char_length(user_agent) <= 512);

-- session.revoked is attributed to the user who ended the session from
-- /me/sessions: the writer names them in the transaction-local setting
-- iamkit.session_actor (a user id); every other way a session ends stays a
-- system event, as before. Children ended with their parent share it.
CREATE OR REPLACE FUNCTION session_event() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  s sessions%ROWTYPE;
  kind text := 'user';
  actor text;
  t text;
  revoker text;
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
  revoker := nullif(current_setting('iamkit.session_actor', true), '');
  IF t = 'session.revoked' AND revoker IS NOT NULL AND TG_OP = 'UPDATE' THEN
    actor := revoker;
  ELSIF s.actor_id IS NOT NULL THEN
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
