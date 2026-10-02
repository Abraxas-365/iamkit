-- 046: Event webhooks (subscriptions + delivery outbox).
--
-- An operator subscribes an HTTPS endpoint to event types (exact such as
-- user.created, families such as user.*, or none = every type). Each event
-- inserted into events (045) queues one event_deliveries row per matching
-- active subscription in the same transaction, so a delivery can never be
-- missed even when transactions commit out of id order. Background workers
-- lease only the oldest pending row of each subscription (FOR UPDATE SKIP
-- LOCKED, safe on every replica), so a subscription receives its events in
-- order with one in flight; they are signed per Standard Webhooks and
-- retried with backoff for 24 hours; a subscription failing for 3 days is
-- disabled.
CREATE TABLE event_subscriptions (
  id              uuid        PRIMARY KEY,
  environment_id  uuid        NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  name            text        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  url             text        NOT NULL,
  types           text[]      NOT NULL DEFAULT '{}',
  secret_sealed   text        NOT NULL,
  -- The secret replaced by the last rotation keeps signing until
  -- previous_expires_at, so receivers can switch without dropping calls.
  previous_sealed     text,
  previous_expires_at timestamptz,
  active          boolean     NOT NULL DEFAULT true,
  -- Set by the first failed attempt after a success, cleared by a success.
  failing_since   timestamptz,
  disabled_reason text        NOT NULL DEFAULT '',
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX event_subscriptions_environment ON event_subscriptions (environment_id) WHERE active;

CREATE TABLE event_deliveries (
  id              bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  subscription_id uuid        NOT NULL REFERENCES event_subscriptions(id) ON DELETE CASCADE,
  environment_id  uuid        NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  -- Not a foreign key: events are pruned after their retention.
  event_id        bigint      NOT NULL,
  event_type      text        NOT NULL,
  status          text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed')),
  attempts        int         NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  response_status int,
  last_error      text        NOT NULL DEFAULT '',
  queued_at       timestamptz NOT NULL DEFAULT now(),
  -- Retries stop 24 hours after the first attempt (a subscription sends
  -- one event at a time, so a backlog must not age out while it waits).
  first_attempt_at timestamptz,
  finished_at     timestamptz
);
CREATE INDEX event_deliveries_pending ON event_deliveries (subscription_id, id) WHERE status = 'pending';
CREATE INDEX event_deliveries_subscription ON event_deliveries (subscription_id, id);
CREATE INDEX event_deliveries_finished ON event_deliveries (finished_at) WHERE status <> 'pending';

CREATE FUNCTION queue_event_deliveries() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO event_deliveries (subscription_id, environment_id, event_id, event_type)
  SELECT s.id, NEW.environment_id, NEW.id, NEW.type
  FROM event_subscriptions s
  WHERE s.environment_id = NEW.environment_id AND s.active
    AND (s.types = '{}' OR NEW.type = ANY (s.types) OR split_part(NEW.type, '.', 1) || '.*' = ANY (s.types));
  RETURN NULL;
END $$;
CREATE TRIGGER queue_event_deliveries AFTER INSERT ON events
  FOR EACH ROW EXECUTE FUNCTION queue_event_deliveries();

-- iam:webhooks:read / iam:webhooks:write open subscriptions to /api/v1.
UPDATE resources SET permissions = permissions || ARRAY['iam:webhooks:read']
WHERE prefix = 'iam' AND NOT 'iam:webhooks:read' = ANY(permissions);
UPDATE resources SET permissions = permissions || ARRAY['iam:webhooks:write']
WHERE prefix = 'iam' AND NOT 'iam:webhooks:write' = ANY(permissions);
