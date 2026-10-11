-- App audit logs and log streams.
--
-- audit_log_actions: the actions an environment's applications may emit
-- (invoice.paid, …), each with the target types it accepts and optional
-- JSON Schemas (2020-12) for the metadata objects; every schema change bumps
-- version and events record the version they were validated with.
CREATE TABLE audit_log_actions (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    target_types text[] DEFAULT '{}'::text[] NOT NULL,
    -- {"metadata": schema, "actor": schema, "targets": {"<type>": schema}};
    -- every member optional.
    schema jsonb DEFAULT '{}'::jsonb NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_log_actions_name_check CHECK ((name ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'::text) AND length(name) <= 100),
    CONSTRAINT audit_log_actions_description_check CHECK (length(description) <= 500),
    CONSTRAINT audit_log_actions_schema_check CHECK ((jsonb_typeof(schema) = 'object'::text)),
    CONSTRAINT audit_log_actions_version_check CHECK ((version >= 1)),
    CONSTRAINT audit_log_actions_pkey PRIMARY KEY (id),
    CONSTRAINT audit_log_actions_environment_id_name_key UNIQUE (environment_id, name),
    CONSTRAINT audit_log_actions_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);

-- audit_log_events: what the applications emitted, per organization.
-- Immutable: refuse_audit_log_change allows no UPDATE and only the prune
-- job's DELETE (transaction-local iamkit.audit_log_prune = 'on') or the
-- cascade of a deleted environment / organization. seq orders the log
-- (cursor); id is the public identifier. action is a copy of the action
-- name (an action may be deleted later; its events stay).
CREATE TABLE audit_log_events (
    seq bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    action text NOT NULL,
    version integer NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    -- {"type","id","name"?,"metadata"?}
    actor jsonb NOT NULL,
    -- [{"type","id","name"?,"metadata"?}]
    targets jsonb DEFAULT '[]'::jsonb NOT NULL,
    -- {"location"?,"user_agent"?}
    context jsonb DEFAULT '{}'::jsonb NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    -- Idempotency-Key header and the SHA-256 of the canonical request it
    -- was first used with.
    idempotency_key text,
    request_hash bytea,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_log_events_actor_check CHECK ((jsonb_typeof(actor) = 'object'::text)),
    CONSTRAINT audit_log_events_targets_check CHECK ((jsonb_typeof(targets) = 'array'::text)),
    CONSTRAINT audit_log_events_context_check CHECK ((jsonb_typeof(context) = 'object'::text)),
    CONSTRAINT audit_log_events_metadata_check CHECK ((jsonb_typeof(metadata) = 'object'::text)),
    CONSTRAINT audit_log_events_idempotency_check CHECK (((idempotency_key IS NULL) = (request_hash IS NULL)) AND length(idempotency_key) <= 255),
    CONSTRAINT audit_log_events_pkey PRIMARY KEY (seq),
    CONSTRAINT audit_log_events_id_key UNIQUE (id),
    CONSTRAINT audit_log_events_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE,
    CONSTRAINT audit_log_events_organization_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX audit_log_events_environment ON audit_log_events USING btree (environment_id, seq);
CREATE INDEX audit_log_events_organization ON audit_log_events USING btree (environment_id, organization_id, seq);
CREATE INDEX audit_log_events_action ON audit_log_events USING btree (environment_id, action, seq);
CREATE INDEX audit_log_events_actor ON audit_log_events USING btree (environment_id, ((actor ->> 'id')), seq);
CREATE INDEX audit_log_events_targets ON audit_log_events USING gin (targets jsonb_path_ops);
CREATE INDEX audit_log_events_created ON audit_log_events USING btree (created_at);
CREATE UNIQUE INDEX audit_log_events_idempotency ON audit_log_events USING btree (environment_id, idempotency_key) WHERE (idempotency_key IS NOT NULL);

CREATE FUNCTION refuse_audit_log_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP = 'DELETE' AND (
       current_setting('iamkit.audit_log_prune', true) = 'on'
       OR NOT EXISTS (SELECT 1 FROM organizations WHERE id = OLD.organization_id AND environment_id = OLD.environment_id)) THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'audit log events are immutable' USING ERRCODE = '55000';
END $$;
CREATE TRIGGER refuse_audit_log_change BEFORE UPDATE OR DELETE ON audit_log_events
  FOR EACH ROW
  EXECUTE FUNCTION refuse_audit_log_change();

-- log_streams: delivery of events to a SIEM or object storage.
-- organization_id NULL = an environment stream (sources events and/or
-- audit_logs, every organization); set = an organization stream (its
-- audit_logs only — IAMKit's own events never leave per organization).
-- config holds the destination's non-secret settings; the secret (API key,
-- HEC token, secret access key, whsec_) is sealed and never returned.
-- previous_sealed keeps a rotated https secret signing until
-- previous_expires_at. Disabling and failure follow event_subscriptions.
CREATE TABLE log_streams (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid,
    name text NOT NULL,
    destination text NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    secret_sealed text NOT NULL,
    previous_sealed text,
    previous_expires_at timestamp with time zone,
    sources text[] NOT NULL,
    active boolean DEFAULT true NOT NULL,
    failing_since timestamp with time zone,
    disabled_reason text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT log_streams_name_check CHECK (((length(name) >= 1) AND (length(name) <= 100))),
    CONSTRAINT log_streams_destination_check CHECK ((destination = ANY (ARRAY['datadog'::text, 'splunk'::text, 's3'::text, 'https'::text]))),
    CONSTRAINT log_streams_config_check CHECK ((jsonb_typeof(config) = 'object'::text)),
    CONSTRAINT log_streams_sources_check CHECK (cardinality(sources) > 0
      AND sources <@ ARRAY['events'::text, 'audit_logs'::text]
      AND (organization_id IS NULL OR sources = ARRAY['audit_logs'::text])),
    CONSTRAINT log_streams_pkey PRIMARY KEY (id),
    CONSTRAINT log_streams_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE,
    CONSTRAINT log_streams_organization_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX log_streams_environment ON log_streams USING btree (environment_id, organization_id);

-- Log stream outbox: one row per record per stream, filled in the record's
-- transaction. The worker sends a stream's oldest pending rows as one batch
-- (batch = the batch's first row id, kept across retries so a retried batch
-- is the same records and the same object key). source_seq is events.id or
-- audit_log_events.seq; not a foreign key: pruned records deliver as failed.
CREATE TABLE log_stream_deliveries (
    id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
    stream_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    source text NOT NULL,
    source_seq bigint NOT NULL,
    batch bigint,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    response_status integer,
    last_error text DEFAULT ''::text NOT NULL,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    first_attempt_at timestamp with time zone,
    finished_at timestamp with time zone,
    CONSTRAINT log_stream_deliveries_source_check CHECK ((source = ANY (ARRAY['events'::text, 'audit_logs'::text]))),
    CONSTRAINT log_stream_deliveries_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'delivered'::text, 'failed'::text]))),
    CONSTRAINT log_stream_deliveries_pkey PRIMARY KEY (id),
    CONSTRAINT log_stream_deliveries_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE,
    CONSTRAINT log_stream_deliveries_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES log_streams(id) ON DELETE CASCADE
);
CREATE INDEX log_stream_deliveries_pending ON log_stream_deliveries USING btree (stream_id, id) WHERE (status = 'pending'::text);
CREATE INDEX log_stream_deliveries_stream ON log_stream_deliveries USING btree (stream_id, id);
CREATE INDEX log_stream_deliveries_finished ON log_stream_deliveries USING btree (finished_at) WHERE (status <> 'pending'::text);

-- Queue every new record for the streams that take it: active ones and
-- those disabled for failing (re-enabling resumes); an operator's disable
-- stops queuing.
CREATE FUNCTION queue_log_stream_events() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  INSERT INTO log_stream_deliveries (stream_id, environment_id, source, source_seq)
  SELECT s.id, NEW.environment_id, 'events', NEW.id
  FROM log_streams s
  WHERE s.environment_id = NEW.environment_id AND s.organization_id IS NULL
    AND 'events' = ANY (s.sources) AND (s.active OR s.disabled_reason = 'failing');
  RETURN NULL;
END $$;
CREATE TRIGGER queue_log_stream_events AFTER INSERT ON events
  FOR EACH ROW
  EXECUTE FUNCTION queue_log_stream_events();

CREATE FUNCTION queue_log_stream_audit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  INSERT INTO log_stream_deliveries (stream_id, environment_id, source, source_seq)
  SELECT s.id, NEW.environment_id, 'audit_logs', NEW.seq
  FROM log_streams s
  WHERE s.environment_id = NEW.environment_id
    AND (s.organization_id IS NULL OR s.organization_id = NEW.organization_id)
    AND 'audit_logs' = ANY (s.sources) AND (s.active OR s.disabled_reason = 'failing');
  RETURN NULL;
END $$;
CREATE TRIGGER queue_log_stream_audit AFTER INSERT ON audit_log_events
  FOR EACH ROW
  EXECUTE FUNCTION queue_log_stream_audit();

-- Ingest limit (usage.LimitAuditEvents).
ALTER TABLE environment_limits ADD COLUMN audit_events_per_minute bigint;
ALTER TABLE environment_limits ADD CONSTRAINT environment_limits_audit_events_per_minute_check CHECK ((audit_events_per_minute >= 0));

-- Setup links may hand out log stream configuration.
ALTER TABLE org_setup_links DROP CONSTRAINT org_setup_links_intents_check;
ALTER TABLE org_setup_links ADD CONSTRAINT org_setup_links_intents_check
  CHECK (cardinality(intents) > 0 AND intents <@ ARRAY['sso'::text, 'directory'::text, 'domains'::text, 'log_streams'::text]);

-- New IAM resource permissions (authorization.IAMResourcePermissions):
-- iam:audit-logs:read / :write (emit) / :manage (actions, log streams), and
-- the organization-bound iam:org:log-streams:write. No role or service
-- account gains the iam:* ones. org_owner holds every organization
-- permission (orgadmin.Principal.Owner), so it gains the new one.
UPDATE resources
   SET permissions = permissions || ARRAY(
         SELECT p FROM unnest(ARRAY['iam:audit-logs:read', 'iam:audit-logs:write', 'iam:audit-logs:manage', 'iam:org:log-streams:write']) AS p
          WHERE NOT (p = ANY (permissions)))
 WHERE prefix = 'iam';
-- role_updated would end every live session of every owner; tokens pick the
-- permission up at their next sign-in instead.
ALTER TABLE roles DISABLE TRIGGER role_updated;
UPDATE roles
   SET permissions = array_append(permissions, 'iam:org:log-streams:write')
 WHERE system_role = 'org_owner'
   AND NOT ('iam:org:log-streams:write' = ANY (permissions));
ALTER TABLE roles ENABLE TRIGGER role_updated;
