-- MCP authorization, phase (d): consent, administrator grants, connected
-- apps and access token lifetime. Additive to 023.

-- D29: whether a client's users must consent to what it asks for. Clients
-- named outside IAMKit (metadata documents, dynamic registration) and
-- clients made from a preset template are third parties: always
-- 'required'. Operator-registered clients are first-party by default
-- ('skip'); an operator may require consent for one. The CHECK holds
-- third parties to 'required', so their writers must name it.
ALTER TABLE oauth_clients
    ADD COLUMN consent_policy text DEFAULT 'skip'::text NOT NULL;
UPDATE oauth_clients SET consent_policy = 'required' WHERE source <> 'registered' OR preset <> '';
ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_consent_policy_check CHECK ((consent_policy = ANY (ARRAY['required'::text, 'skip'::text]))),
    ADD CONSTRAINT oauth_clients_third_party_consent_check CHECK (((source = 'registered'::text AND preset = ''::text) OR consent_policy = 'required'::text));

-- D31: per_user (each user consents) or admin_granted (an administrator
-- may grant scopes to a client for every user, or one organization's).
-- D36: lifetime of the resource flow's access tokens: the window in which
-- a token outlives a block or revocation for a server that does not
-- introspect. At most the idle TTL (held by the domain and at use: a
-- lowered policy may trim the idle TTL below it).
ALTER TABLE protected_resources
    ADD COLUMN consent_mode text DEFAULT 'per_user'::text NOT NULL,
    ADD COLUMN access_token_ttl_seconds bigint DEFAULT 900 NOT NULL,
    ADD CONSTRAINT protected_resources_consent_mode_check CHECK ((consent_mode = ANY (ARRAY['per_user'::text, 'admin_granted'::text]))),
    ADD CONSTRAINT protected_resources_access_token_ttl_check CHECK (((access_token_ttl_seconds >= 60) AND (access_token_ttl_seconds <= 3600)));

-- D30: where users consent. 'hosted': IAMKit's consent page (also the
-- fallback of a custom sign-in UI that does not implement consent);
-- 'custom': the environment's own sign-in UI asks through the
-- authorization ticket's consent endpoints.
ALTER TABLE protected_resource_policies
    ADD COLUMN consent_ui text DEFAULT 'hosted'::text NOT NULL,
    ADD CONSTRAINT protected_resource_policies_consent_ui_check CHECK ((consent_ui = ANY (ARRAY['hosted'::text, 'custom'::text])));

-- What a user agreed a client may do in one organization, at a protected
-- resource (NULL: the client's own application, for third-party OpenID
-- Connect clients). One live row per key; scopes only grow while it lives
-- (a new consent adds to it). Revoked rows stay as records (revoked_at,
-- revoked_reason) until oauth_consent_prune.
CREATE TABLE oauth_consents (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    client_id uuid NOT NULL,
    protected_resource_id uuid,
    scopes text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    revoked_reason text,
    CONSTRAINT oauth_consents_pkey PRIMARY KEY (id),
    CONSTRAINT oauth_consents_scopes_check CHECK (((cardinality(scopes) >= 1) AND (cardinality(scopes) <= 200))),
    CONSTRAINT oauth_consents_revoked_check CHECK (((revoked_at IS NULL) = (revoked_reason IS NULL))),
    CONSTRAINT oauth_consents_membership_fkey FOREIGN KEY (environment_id, organization_id, user_id) REFERENCES memberships(environment_id, organization_id, user_id) ON DELETE CASCADE,
    CONSTRAINT oauth_consents_client_fkey FOREIGN KEY (client_id, environment_id) REFERENCES oauth_clients(id, environment_id) ON DELETE CASCADE,
    CONSTRAINT oauth_consents_protected_resource_fkey FOREIGN KEY (protected_resource_id, environment_id) REFERENCES protected_resources(id, environment_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX oauth_consents_live ON oauth_consents USING btree (environment_id, user_id, organization_id, client_id, protected_resource_id) NULLS NOT DISTINCT
    WHERE (revoked_at IS NULL);
CREATE INDEX oauth_consents_client ON oauth_consents USING btree (client_id) WHERE (revoked_at IS NULL);
CREATE INDEX oauth_consents_prune ON oauth_consents USING btree (revoked_at) WHERE (revoked_at IS NOT NULL);

-- D31: scopes an administrator granted a client at a protected resource
-- for every user of the environment (organization_id NULL) or of one
-- organization, optionally until expires_at (client_grant_expire revokes
-- it then, with an event). Revoked rows stay as records.
CREATE TABLE oauth_client_grants (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    protected_resource_id uuid NOT NULL,
    client_id uuid NOT NULL,
    organization_id uuid,
    scopes text[] NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    revoked_reason text,
    CONSTRAINT oauth_client_grants_pkey PRIMARY KEY (id),
    CONSTRAINT oauth_client_grants_scopes_check CHECK (((cardinality(scopes) >= 1) AND (cardinality(scopes) <= 200))),
    CONSTRAINT oauth_client_grants_revoked_check CHECK (((revoked_at IS NULL) = (revoked_reason IS NULL))),
    CONSTRAINT oauth_client_grants_protected_resource_fkey FOREIGN KEY (protected_resource_id, environment_id) REFERENCES protected_resources(id, environment_id) ON DELETE CASCADE,
    CONSTRAINT oauth_client_grants_client_fkey FOREIGN KEY (client_id, environment_id) REFERENCES oauth_clients(id, environment_id) ON DELETE CASCADE,
    CONSTRAINT oauth_client_grants_organization_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX oauth_client_grants_live ON oauth_client_grants USING btree (protected_resource_id, client_id, organization_id) NULLS NOT DISTINCT
    WHERE (revoked_at IS NULL);
CREATE INDEX oauth_client_grants_expire ON oauth_client_grants USING btree (expires_at) WHERE ((revoked_at IS NULL) AND (expires_at IS NOT NULL));
CREATE INDEX oauth_client_grants_prune ON oauth_client_grants USING btree (revoked_at) WHERE (revoked_at IS NOT NULL);

-- D30: an authorization waiting for consent keeps the signed-in session it
-- will be issued for and the scopes the user was asked about (approving
-- records exactly those). consent_session_hosted: the hosted pages signed
-- that session in for this authorization, so rejecting ends it (a custom
-- sign-in UI's own session is left alone).
ALTER TABLE oauth_authorizations
    ADD COLUMN consent_session_id uuid,
    ADD COLUMN consent_scopes text[],
    ADD COLUMN consent_session_hosted boolean DEFAULT false NOT NULL,
    ADD CONSTRAINT oauth_authorizations_consent_check CHECK ((((consent_session_id IS NULL) AND (consent_scopes IS NULL))
        OR ((consent_session_id IS NOT NULL) AND (cardinality(consent_scopes) >= 1)))),
    ADD CONSTRAINT oauth_authorizations_consent_session_fkey FOREIGN KEY (consent_session_id) REFERENCES sessions(id) ON DELETE CASCADE;

-- The protected resource a session's grant is for (set with
-- oauth_client_id when the authorization binds it): revoking a consent or
-- a grant ends the sessions of that client at that resource only, and
-- connected apps list them.
ALTER TABLE sessions
    ADD COLUMN protected_resource_id uuid,
    ADD CONSTRAINT sessions_protected_resource_fkey FOREIGN KEY (protected_resource_id, environment_id) REFERENCES protected_resources(id, environment_id) ON DELETE SET NULL (protected_resource_id);
-- An external client exists for one protected resource: its sessions are
-- that resource's grants.
UPDATE sessions s SET protected_resource_id = c.protected_resource_id
  FROM oauth_clients c
 WHERE c.id = s.oauth_client_id AND c.source <> 'registered' AND s.revoked_at IS NULL;
CREATE INDEX sessions_user_oauth ON sessions USING btree (environment_id, user_id, oauth_client_id) WHERE ((oauth_client_id IS NOT NULL) AND (revoked_at IS NULL));
