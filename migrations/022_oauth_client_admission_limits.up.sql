-- MCP authorization, phase (b), second review (W6). Additive to 021.

-- M-3: the organization a user asked from, so one organization's pending
-- requests can be capped (config.ClientAccessRequestsPerOrganization). Null
-- for requests made without one, and when the organization is deleted.
ALTER TABLE oauth_client_access_requests
    ADD COLUMN organization_id uuid,
    ADD CONSTRAINT oauth_client_access_requests_organization_fkey FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL;

-- L-2: a user's live requests are counted per request (M-3) and go with the
-- user (the foreign key cascade), neither found by the primary key
-- (client_id, user_id).
CREATE INDEX oauth_client_access_requests_user ON oauth_client_access_requests USING btree (user_id, requested_at);
CREATE INDEX oauth_client_access_requests_organization ON oauth_client_access_requests USING btree (organization_id, requested_at) WHERE (organization_id IS NOT NULL);

-- L-2: authorization tickets of a protected resource, found when it is
-- deactivated, deleted or counted.
CREATE INDEX oauth_authorizations_protected_resource ON oauth_authorizations USING btree (protected_resource_id) WHERE (protected_resource_id IS NOT NULL);

-- L-2: the clients an allowlist entry or preset covers are those whose URL
-- starts with the entry's origin (external_id LIKE 'origin%'): a prefix scan,
-- whatever the database collation.
CREATE INDEX oauth_clients_external_prefix ON oauth_clients USING btree (environment_id, external_id text_pattern_ops) WHERE (source = 'cimd'::text);
