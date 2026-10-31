-- D39: security event retention. Every event gets a retention class when it
-- is inserted ('security' for the sign-in, session, token, credential and
-- consent trail, 'default' for the rest), from the SQL function
-- event_retention_class, which repeats the Go catalog (event.SecurityFamilies,
-- event.SecurityTypes; internal/architecture keeps the two equal). The class
-- is stored, never derived by a pattern when pruning. Triggers that write
-- events (session.*, api_key.revoked, risk.*, saml.*) get it as well, as
-- the trigger is on the table.
--
-- The deployment sets a ceiling per class (IAMKIT_EVENT_RETENTION,
-- IAMKIT_SECURITY_EVENT_RETENTION); event_retention_policies lets an
-- environment keep events for less (NULL: the ceiling), never for more.

CREATE FUNCTION event_retention_class(t text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
  SELECT CASE
    WHEN split_part(t, '.', 1) IN ('session', 'sign_in', 'login', 'risk', 'impersonation', 'token', 'device', 'oauth_client', 'oauth_consent', 'api_key', 'mfa', 'identity', 'signing_key', 'saml')
      OR t IN ('user.locked', 'user.unlocked', 'user.password_changed', 'user.password_change_required', 'user.sessions_revoked')
    THEN 'security'
    ELSE 'default'
  END
$$;

CREATE FUNCTION set_event_retention_class() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.retention_class := event_retention_class(NEW.type);
  RETURN NEW;
END $$;

-- The default only lets the column be added to the existing rows; the
-- trigger sets the class of every new one.
ALTER TABLE events ADD COLUMN retention_class text DEFAULT 'default'::text NOT NULL;
ALTER TABLE events ALTER COLUMN retention_class DROP DEFAULT;
ALTER TABLE events ADD CONSTRAINT events_retention_class_check CHECK ((retention_class = ANY (ARRAY['security'::text, 'default'::text])));
CREATE TRIGGER event_retention_class BEFORE INSERT ON events
  FOR EACH ROW
  EXECUTE FUNCTION set_event_retention_class();

-- One UPDATE: the migration is transactional, so it cannot be batched. The
-- event log of a deployment this early is small; a larger one should run
-- this statement in batches by id before upgrading (see the upgrade notes).
UPDATE events SET retention_class = 'security' WHERE event_retention_class(type) = 'security';

-- The prune job deletes by environment, class and age, in batches. The
-- index replaces events_created, which only the prune read. Starting with
-- the environment gives each environment's cutoff an exact range.
DROP INDEX events_created;
CREATE INDEX events_retention ON events USING btree (environment_id, retention_class, created_at);

CREATE TABLE event_retention_policies (
    environment_id uuid NOT NULL,
    security_retention_seconds bigint,
    default_retention_seconds bigint,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT event_retention_policies_pkey PRIMARY KEY (environment_id),
    CONSTRAINT event_retention_policies_security_check CHECK ((security_retention_seconds >= 86400)),
    CONSTRAINT event_retention_policies_default_check CHECK ((default_retention_seconds >= 86400)),
    CONSTRAINT event_retention_policies_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);
