-- 052: Actions (E4) — synchronous hooks. An operator registers targets
-- (HTTPS endpoints IAMKit calls, signed per Standard Webhooks) and binds
-- them to conditions: functions of the sign-in and token flows
-- (function:pre_sign_in, function:pre_access_token, …) and a few
-- allow-listed management requests (request:user.create, …). Targets of a
-- condition run in the order listed. action_calls keeps a short log of
-- recent calls for the console (pruned by the action_call_prune job).
CREATE TABLE action_targets (
  id                 uuid        PRIMARY KEY,
  environment_id     uuid        NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  name               text        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  url                text        NOT NULL,
  kind               text        NOT NULL CHECK (kind IN ('call', 'webhook', 'async')),
  timeout_ms         int         NOT NULL CHECK (timeout_ms BETWEEN 100 AND 10000),
  interrupt_on_error boolean     NOT NULL DEFAULT false,
  secret_sealed      text        NOT NULL,
  -- A rotated secret keeps signing until previous_expires_at.
  previous_sealed     text,
  previous_expires_at timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX action_targets_environment ON action_targets (environment_id);

CREATE TABLE action_executions (
  environment_id uuid        NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  condition      text        NOT NULL,
  -- Ordered; a deleted target is removed from every execution (trigger).
  target_ids     uuid[]      NOT NULL CHECK (cardinality(target_ids) BETWEEN 1 AND 5),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (environment_id, condition)
);

CREATE FUNCTION action_target_deleted() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  UPDATE action_executions SET target_ids = array_remove(target_ids, OLD.id), updated_at = now()
  WHERE environment_id = OLD.environment_id AND OLD.id = ANY (target_ids) AND cardinality(target_ids) > 1;
  DELETE FROM action_executions
  WHERE environment_id = OLD.environment_id AND target_ids = ARRAY[OLD.id];
  RETURN OLD;
END $$;
CREATE TRIGGER action_target_deleted BEFORE DELETE ON action_targets
  FOR EACH ROW EXECUTE FUNCTION action_target_deleted();

CREATE TABLE action_calls (
  id             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  environment_id uuid        NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  target_id      uuid        NOT NULL REFERENCES action_targets(id) ON DELETE CASCADE,
  condition      text        NOT NULL,
  -- ok, denied, failed, skipped (circuit open)
  outcome        text        NOT NULL CHECK (outcome IN ('ok', 'denied', 'failed', 'skipped')),
  status         int,
  duration_ms    int         NOT NULL DEFAULT 0,
  error          text        NOT NULL DEFAULT '',
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX action_calls_environment ON action_calls (environment_id, id DESC);
CREATE INDEX action_calls_target ON action_calls (target_id, id DESC);
CREATE INDEX action_calls_created ON action_calls (created_at);
