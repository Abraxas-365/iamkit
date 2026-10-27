-- Protected resources (RFC 9728 resource servers, e.g. remote MCP servers):
-- a resource whose audience is its canonical URL (oauth.CanonicalResource)
-- and that OAuth clients reach with the RFC 8707 resource parameter. The
-- URL is unique in the whole deployment, so a token for one environment is
-- never accepted by a server of another.
CREATE TABLE protected_resources (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    application_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    uri text NOT NULL,
    name text NOT NULL,
    -- Scopes a client gets when it asks for none (and the PRM's
    -- scopes_supported); always within the resource's permission catalog.
    default_scopes text[] DEFAULT '{}'::text[] NOT NULL,
    -- Refresh token inactivity window and absolute session lifetime of the
    -- authorizations for this resource (seconds).
    idle_ttl_seconds bigint DEFAULT 604800 NOT NULL,
    max_ttl_seconds bigint DEFAULT 2592000 NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT protected_resources_pkey PRIMARY KEY (id),
    CONSTRAINT protected_resources_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT protected_resources_uri_key UNIQUE (uri),
    CONSTRAINT protected_resources_resource_key UNIQUE (environment_id, resource_id),
    CONSTRAINT protected_resources_name_check CHECK (((length(TRIM(BOTH FROM name)) >= 1) AND (length(name) <= 200))),
    CONSTRAINT protected_resources_ttl_check CHECK (((idle_ttl_seconds > 0) AND (max_ttl_seconds > 0) AND (idle_ttl_seconds <= max_ttl_seconds))),
    CONSTRAINT protected_resources_application_resource_fkey FOREIGN KEY (environment_id, application_id, resource_id) REFERENCES application_resources(environment_id, application_id, resource_id)
);
CREATE TRIGGER record_changes AFTER UPDATE ON protected_resources
  FOR EACH ROW
  EXECUTE FUNCTION record_changes();

-- The URI is the resource's audience (the aud of every token for it).
CREATE FUNCTION protected_resource_uri() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM resources WHERE id = NEW.resource_id AND environment_id = NEW.environment_id AND audience = NEW.uri) THEN
    RAISE EXCEPTION 'protected resource uri must be its resource audience' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER protected_resource_uri BEFORE INSERT OR UPDATE OF uri, resource_id ON protected_resources
  FOR EACH ROW
  EXECUTE FUNCTION protected_resource_uri();

-- A resource with a protected resource keeps its audience.
CREATE FUNCTION protected_resource_audience() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM protected_resources WHERE resource_id = OLD.id AND environment_id = OLD.environment_id) THEN
    RAISE EXCEPTION 'the audience of a protected resource cannot change' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER protected_resource_audience BEFORE UPDATE OF audience ON resources
  FOR EACH ROW WHEN ((old.audience IS DISTINCT FROM new.audience))
  EXECUTE FUNCTION protected_resource_audience();

-- Per environment ceilings of the protected resources' TTLs (absent row:
-- oauth.DefaultProtectedResourcePolicy). Lowering one trims the servers
-- above it in the same transaction.
CREATE TABLE protected_resource_policies (
    environment_id uuid NOT NULL,
    max_idle_ttl_seconds bigint NOT NULL,
    max_lifetime_ttl_seconds bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT protected_resource_policies_pkey PRIMARY KEY (environment_id),
    CONSTRAINT protected_resource_policies_check CHECK (((max_idle_ttl_seconds > 0) AND (max_lifetime_ttl_seconds > 0) AND (max_idle_ttl_seconds <= max_lifetime_ttl_seconds))),
    CONSTRAINT protected_resource_policies_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);

-- New IAM resource permissions: iam:protected-resources:read / :write. No
-- role or service account gains them.
UPDATE resources
   SET permissions = permissions || ARRAY(
         SELECT p FROM unnest(ARRAY['iam:protected-resources:read', 'iam:protected-resources:write']) AS p
          WHERE NOT (p = ANY (permissions)))
 WHERE prefix = 'iam';
