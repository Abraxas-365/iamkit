-- Organization setup links: an expiring link an operator or an organization
-- owner gives the customer's IT administrator (who has no IAMKit account) to
-- configure single sign-on, SCIM directory sync and domains. Only the hash of
-- the link secret (ik_setup_…) is stored.
CREATE TABLE org_setup_links (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    intents text[] NOT NULL,
    secret_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_by text NOT NULL DEFAULT ''::text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    CONSTRAINT org_setup_links_pkey PRIMARY KEY (id),
    CONSTRAINT org_setup_links_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT org_setup_links_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT org_setup_links_intents_check CHECK (cardinality(intents) > 0 AND intents <@ ARRAY['sso'::text, 'directory'::text, 'domains'::text]),
    CONSTRAINT org_setup_links_organization_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX org_setup_links_organization ON org_setup_links USING btree (environment_id, organization_id, created_at DESC);

-- The bearer a link is exchanged for: opaque (ik_setupsess_…, hash stored),
-- short-lived and tied to its link, so revoking or expiring the link ends
-- every session at once (validation joins the link).
CREATE TABLE org_setup_sessions (
    token_hash bytea NOT NULL,
    link_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT org_setup_sessions_pkey PRIMARY KEY (token_hash),
    CONSTRAINT org_setup_sessions_link_fkey FOREIGN KEY (link_id, environment_id) REFERENCES org_setup_links(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX org_setup_sessions_link ON org_setup_sessions USING btree (link_id);
CREATE INDEX org_setup_sessions_expires ON org_setup_sessions USING btree (expires_at);

-- A new actor kind: setup_link (actor_id = the link id).
ALTER TABLE audit_events DROP CONSTRAINT audit_events_actor_kind_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_actor_kind_check
    CHECK ((actor_kind = ANY (ARRAY['operator'::text, 'user'::text, 'service_account'::text, 'setup_link'::text, 'system'::text])));
ALTER TABLE events DROP CONSTRAINT events_actor_kind_check;
ALTER TABLE events ADD CONSTRAINT events_actor_kind_check
    CHECK ((actor_kind = ANY (ARRAY['operator'::text, 'user'::text, 'service_account'::text, 'directory'::text, 'setup_link'::text, 'system'::text])));

-- Resolve the actor kind and organization of an audit row.
CREATE OR REPLACE FUNCTION audit_event_context() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE id = NEW.actor_id AND environment_id = NEW.environment_id) THEN
        NEW.actor_kind := 'user';
    ELSIF EXISTS (SELECT 1 FROM service_accounts WHERE id = NEW.actor_id AND environment_id = NEW.environment_id) THEN
        NEW.actor_kind := 'service_account';
    ELSIF EXISTS (SELECT 1 FROM org_setup_links WHERE id = NEW.actor_id AND environment_id = NEW.environment_id) THEN
        NEW.actor_kind := 'setup_link';
    END IF;
    IF NEW.organization_id IS NULL THEN
        NEW.organization_id := substring(NEW.target_id FROM '/organizations/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')::uuid;
    END IF;
    RETURN NEW;
END $$;

-- Resolve events.actor_kind when the writer left it NULL.
CREATE OR REPLACE FUNCTION event_actor() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
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
    ELSIF NEW.actor_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND EXISTS (SELECT 1 FROM org_setup_links WHERE id = NEW.actor_id::uuid AND environment_id = NEW.environment_id) THEN
      NEW.actor_kind := 'setup_link';
    ELSE
      NEW.actor_kind := 'operator';
    END IF;
  END IF;
  RETURN NEW;
END $_$;
