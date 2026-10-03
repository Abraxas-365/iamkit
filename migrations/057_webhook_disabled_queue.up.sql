-- 057: A subscription disabled for failing keeps queuing (F-037).
--
-- docs/reference/event-webhooks.md: a subscription the worker disables
-- after three days of failures (disabled_reason 'failing') keeps queuing
-- events, so re-enabling it resumes where it stopped. The trigger queued
-- for active subscriptions only, losing every event of the disabled
-- period. An operator's disable (disabled_reason '') still stops queuing.
CREATE OR REPLACE FUNCTION queue_event_deliveries() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO event_deliveries (subscription_id, environment_id, event_id, event_type)
  SELECT s.id, NEW.environment_id, NEW.id, NEW.type
  FROM event_subscriptions s
  WHERE s.environment_id = NEW.environment_id AND (s.active OR s.disabled_reason = 'failing')
    AND (s.types = '{}' OR NEW.type = ANY (s.types) OR split_part(NEW.type, '.', 1) || '.*' = ANY (s.types));
  RETURN NULL;
END $$;
