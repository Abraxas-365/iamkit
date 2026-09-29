-- 029: OAuth 2.0 Token Exchange (RFC 8693).
--
-- Resource exchange: a user's access token for one resource becomes a token
-- for another resource of the same application. The new token needs a
-- session for that resource; it is a child of the original session, lives
-- no longer than it and ends with it. One live child per parent and resource.
ALTER TABLE sessions
  ADD COLUMN parent_session_id uuid REFERENCES sessions(id) ON DELETE CASCADE;
CREATE UNIQUE INDEX sessions_exchange_child
  ON sessions (parent_session_id, resource_id)
  WHERE parent_session_id IS NOT NULL AND revoked_at IS NULL;

CREATE FUNCTION end_child_sessions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE sessions SET revoked_at = NEW.revoked_at
    WHERE parent_session_id = NEW.id AND revoked_at IS NULL;
  RETURN NULL;
END $$;

CREATE TRIGGER session_children_ended
  AFTER UPDATE OF revoked_at ON sessions FOR EACH ROW
  WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
  EXECUTE FUNCTION end_child_sessions();

-- Impersonation by a service account: a user session whose actor is the
-- account (never an operator), with a reason like operator impersonation.
-- Only accounts an owner allowed may do it; existing accounts may not.
ALTER TABLE service_accounts
  ADD COLUMN can_impersonate boolean NOT NULL DEFAULT false;
ALTER TABLE sessions
  ADD COLUMN actor_account_id uuid REFERENCES service_accounts(id) ON DELETE CASCADE;
ALTER TABLE sessions DROP CONSTRAINT impersonation_attribution;
ALTER TABLE sessions ADD CONSTRAINT impersonation_attribution CHECK (
  (actor_id IS NULL AND actor_account_id IS NULL AND impersonation_reason IS NULL)
  OR (num_nonnulls(actor_id, actor_account_id) = 1 AND length(trim(impersonation_reason)) >= 10)
);
