-- MCP authorization, phase (b): OAuth Client ID Metadata Documents
-- (draft-ietf-oauth-client-id-metadata-document). A client whose client_id
-- is an https URL is materialized as an oauth_clients row per protected
-- resource it asks for (source 'cimd'): the internal id stays a uuid (every
-- foreign key is unchanged), external_id is the URL clients send.
ALTER TABLE oauth_clients
    ADD COLUMN source text DEFAULT 'registered'::text NOT NULL,
    ADD COLUMN external_id text,
    ADD COLUMN protected_resource_id uuid,
    -- Admission of an external client: approved (allowlist, open server or
    -- an operator), pending (waiting for IT) or blocked.
    ADD COLUMN admission text DEFAULT 'approved'::text NOT NULL,
    -- An approval with an expiry returns to pending after it.
    ADD COLUMN admission_expires_at timestamp with time zone,
    ADD COLUMN client_name text DEFAULT ''::text NOT NULL,
    ADD COLUMN client_uri text DEFAULT ''::text NOT NULL,
    ADD COLUMN logo_uri text DEFAULT ''::text NOT NULL,
    -- The preset a client was made from (oauth.Presets), '' for none.
    ADD COLUMN preset text DEFAULT ''::text NOT NULL,
    -- http://localhost redirect URIs match on any port (RFC 8252 §7.3), as
    -- loopback IP literals always do. Native clients with a random port.
    ADD COLUMN loopback_any_port boolean DEFAULT false NOT NULL,
    ADD COLUMN metadata_fetched_at timestamp with time zone,
    ADD COLUMN last_used_at timestamp with time zone,
    ADD CONSTRAINT oauth_clients_source_check CHECK ((source = ANY (ARRAY['registered'::text, 'cimd'::text]))),
    ADD CONSTRAINT oauth_clients_admission_check CHECK ((admission = ANY (ARRAY['approved'::text, 'pending'::text, 'blocked'::text]))),
    ADD CONSTRAINT oauth_clients_protected_resource_fkey FOREIGN KEY (protected_resource_id, environment_id) REFERENCES protected_resources(id, environment_id) ON DELETE CASCADE,
    ADD CONSTRAINT oauth_clients_external_key UNIQUE (protected_resource_id, external_id),
    -- Registered clients are approved, named by their uuid, and bound to no
    -- protected resource row of their own.
    ADD CONSTRAINT oauth_clients_registered_check CHECK (((source <> 'registered'::text) OR ((external_id IS NULL) AND (protected_resource_id IS NULL) AND (admission = 'approved'::text) AND (admission_expires_at IS NULL)))),
    -- D16 + D18: an external client is a public client (none) or a
    -- private_key_jwt client whose keys are at a jwks_uri of the client_id's
    -- origin. It authorizes users with the code flow and refreshes; it never
    -- holds a secret, an inline key set, client_credentials, token exchange,
    -- jwt-bearer or impersonation (oauth.Client.Delegable, and
    -- TestExternalClientsNotDelegable in internal/architecture).
    ADD CONSTRAINT oauth_clients_external_check CHECK (((source = 'registered'::text) OR (
        (external_id IS NOT NULL) AND (protected_resource_id IS NOT NULL)
        AND (external_id ~ '^https://[a-z0-9.-]+/[^?#]+$') AND (length(external_id) <= 255)
        AND (token_endpoint_auth_method = ANY (ARRAY['none'::text, 'private_key_jwt'::text]))
        AND (public = (token_endpoint_auth_method = 'none'::text))
        AND ((token_endpoint_auth_method = 'none'::text AND jwks_uri = ''::text)
          OR (token_endpoint_auth_method = 'private_key_jwt'::text AND substring(jwks_uri FROM '^https://[^/?#]+') = substring(external_id FROM '^https://[^/?#]+') AND jwks_uri ~ '^https://[^/?#]+/'))
        AND (jwks IS NULL) AND (secret_hash = '\x'::bytea)
        AND (grant_types @> ARRAY['authorization_code'::text]) AND (grant_types <@ ARRAY['authorization_code'::text, 'refresh_token'::text])
        AND hosted_login AND (system IS NULL) AND (allowed_origins = '{}'::text[])
        AND (backchannel_logout_uri = ''::text) AND (initiate_login_uri = ''::text) AND (preset = ''::text)
    )));

CREATE INDEX oauth_clients_pending ON oauth_clients USING btree (environment_id) WHERE (admission = 'pending'::text);
CREATE INDEX oauth_clients_external ON oauth_clients USING btree (external_id) WHERE (external_id IS NOT NULL);

-- Per protected resource: whether URL client_ids are accepted at all, and
-- whether a client that matches no allowlist entry is admitted (open) or
-- waits for IT (allowlist).
ALTER TABLE protected_resources
    ADD COLUMN allow_client_metadata boolean DEFAULT true NOT NULL,
    ADD COLUMN client_admission text DEFAULT 'allowlist'::text NOT NULL,
    ADD CONSTRAINT protected_resources_client_admission_check CHECK ((client_admission = ANY (ARRAY['allowlist'::text, 'open'::text])));

-- Client metadata documents admitted without review: an exact https origin
-- plus an anchored path prefix (oauth.AllowlistEntry.Matches), for one
-- protected resource or (NULL) every one of the environment.
CREATE TABLE oauth_client_allowlist (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    protected_resource_id uuid,
    origin text NOT NULL,
    path_prefix text NOT NULL,
    preset text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_client_allowlist_pkey PRIMARY KEY (id),
    CONSTRAINT oauth_client_allowlist_origin_check CHECK (((origin ~ '^https://[a-z0-9.-]+$') AND (length(origin) <= 255))),
    CONSTRAINT oauth_client_allowlist_path_check CHECK (((path_prefix ~ '^/') AND (length(path_prefix) <= 255))),
    CONSTRAINT oauth_client_allowlist_key UNIQUE NULLS NOT DISTINCT (environment_id, protected_resource_id, origin, path_prefix),
    CONSTRAINT oauth_client_allowlist_environment_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE,
    CONSTRAINT oauth_client_allowlist_protected_resource_fkey FOREIGN KEY (protected_resource_id, environment_id) REFERENCES protected_resources(id, environment_id) ON DELETE CASCADE
);

-- One oauth_client.access_requested event per (client, user) and
-- config.ClientAccessRequestInterval.
CREATE TABLE oauth_client_access_requests (
    client_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    user_id uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_client_access_requests_pkey PRIMARY KEY (client_id, user_id),
    CONSTRAINT oauth_client_access_requests_client_fkey FOREIGN KEY (client_id, environment_id) REFERENCES oauth_clients(id, environment_id) ON DELETE CASCADE,
    CONSTRAINT oauth_client_access_requests_user_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
