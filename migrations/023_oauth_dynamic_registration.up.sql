-- MCP authorization, phase (c): OAuth 2.0 Dynamic Client Registration
-- (RFC 7591). Additive to 022.

-- A registration made at POST /oauth/register. It is global (RFC 7591 names
-- no resource, so no environment) and inert: no event, no grant, nothing an
-- operator sees. It becomes an oauth_clients row (source 'dcr', external_id
-- = client_id) only at the authorization request of a protected resource
-- that takes dynamically registered clients, and is then admitted like a
-- client of a metadata document. Registrations are immutable (no RFC 7592
-- management) and public: no secret is ever issued.
CREATE TABLE oauth_registrations (
    client_id text NOT NULL,
    client_name text DEFAULT ''::text NOT NULL,
    client_uri text DEFAULT ''::text NOT NULL,
    redirect_uris text[] NOT NULL,
    grant_types text[] NOT NULL,
    software_id text DEFAULT ''::text NOT NULL,
    software_version text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    -- When a client row was last written from it (the sign-in that
    -- materialized it); NULL: never used. An anonymous authorization
    -- request writes nothing, so it cannot keep a registration alive.
    last_used_at timestamp with time zone,
    CONSTRAINT oauth_registrations_pkey PRIMARY KEY (client_id),
    CONSTRAINT oauth_registrations_client_id_check CHECK ((client_id ~ '^dcr_[0-9a-f]{32}$')),
    CONSTRAINT oauth_registrations_redirects_check CHECK (((cardinality(redirect_uris) BETWEEN 1 AND 10))),
    CONSTRAINT oauth_registrations_grants_check CHECK (((grant_types @> ARRAY['authorization_code'::text]) AND (grant_types <@ ARRAY['authorization_code'::text, 'refresh_token'::text]))),
    CONSTRAINT oauth_registrations_lengths_check CHECK (((length(client_name) <= 400) AND (length(client_uri) <= 255) AND (length(software_id) <= 255) AND (length(software_version) <= 255)))
);

-- client_registration_prune: registrations never used go after a day,
-- used ones once no client row holds them and they sat idle.
CREATE INDEX oauth_registrations_prune ON oauth_registrations USING btree ((COALESCE(last_used_at, created_at)));
CREATE INDEX oauth_registrations_unused ON oauth_registrations USING btree (created_at) WHERE (last_used_at IS NULL);

-- Per protected resource: whether dynamically registered clients may ask
-- for it. Off by default: nothing about such a client is verifiable, so a
-- server takes them only when an operator says so (and the environment's
-- dynamic_client_registration feature is on).
ALTER TABLE protected_resources
    ADD COLUMN allow_dynamic_registration boolean DEFAULT false NOT NULL;

-- oauth_clients rows of source 'dcr': a public client (none) named by its
-- registration's client_id, with the same limits as every external client
-- (D16): code flow and refreshes only, hosted login, nothing delegable.
ALTER TABLE oauth_clients
    DROP CONSTRAINT oauth_clients_source_check,
    ADD CONSTRAINT oauth_clients_source_check CHECK ((source = ANY (ARRAY['registered'::text, 'cimd'::text, 'dcr'::text]))),
    DROP CONSTRAINT oauth_clients_external_check,
    ADD CONSTRAINT oauth_clients_external_check CHECK (((source = 'registered'::text) OR (
        (external_id IS NOT NULL) AND (protected_resource_id IS NOT NULL) AND (length(external_id) <= 255)
        AND (
          ((source = 'cimd'::text) AND (external_id ~ '^https://[a-z0-9.-]+/[^?#]+$')
            AND (token_endpoint_auth_method = ANY (ARRAY['none'::text, 'private_key_jwt'::text]))
            AND (public = (token_endpoint_auth_method = 'none'::text))
            AND ((token_endpoint_auth_method = 'none'::text AND jwks_uri = ''::text)
              OR (token_endpoint_auth_method = 'private_key_jwt'::text AND substring(jwks_uri FROM '^https://[^/?#]+') = substring(external_id FROM '^https://[^/?#]+') AND jwks_uri ~ '^https://[^/?#]+/')))
          OR ((source = 'dcr'::text) AND (external_id ~ '^dcr_[0-9a-f]{32}$')
            AND (token_endpoint_auth_method = 'none'::text) AND public AND (jwks_uri = ''::text) AND (logo_uri = ''::text))
        )
        AND (jwks IS NULL) AND (secret_hash = '\x'::bytea)
        AND (grant_types @> ARRAY['authorization_code'::text]) AND (grant_types <@ ARRAY['authorization_code'::text, 'refresh_token'::text])
        AND hosted_login AND (system IS NULL) AND (allowed_origins = '{}'::text[])
        AND (backchannel_logout_uri = ''::text) AND (initiate_login_uri = ''::text) AND (preset = ''::text)
    )));

-- client_pending_prune covers every external source.
DROP INDEX oauth_clients_pending_prune;
CREATE INDEX oauth_clients_pending_prune ON oauth_clients USING btree (discovered_at)
    WHERE ((source <> 'registered'::text) AND (admission = 'pending'::text) AND (last_used_at IS NULL));
