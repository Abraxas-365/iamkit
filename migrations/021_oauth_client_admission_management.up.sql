-- MCP authorization, phase (b), admission management (W2). Additive to 020.
-- Permissions are not new: the admission API, the allowlist and the presets
-- of a protected resource reuse iam:protected-resources:read/write (plan
-- 15.8), so no resource permission list changes here.

-- A client can be blocked, expired or forgotten (and its protected resource
-- deactivated or deleted): every token family, authorization ticket and
-- device code of the client goes in the same transaction, found by client.
CREATE INDEX oauth_requests_client ON oauth_requests USING btree (client_id);
CREATE INDEX oauth_authorizations_client ON oauth_authorizations USING btree (client_id) WHERE (client_id IS NOT NULL);
CREATE INDEX oauth_device_codes_client ON oauth_device_codes USING btree (client_id);
CREATE INDEX sessions_oauth_client ON sessions USING btree (oauth_client_id) WHERE ((oauth_client_id IS NOT NULL) AND (revoked_at IS NULL));

-- The client_admission_expire job finds approvals past their expiry.
CREATE INDEX oauth_clients_admission_expiry ON oauth_clients USING btree (admission_expires_at)
    WHERE ((admission = 'approved'::text) AND (admission_expires_at IS NOT NULL));

-- A template (oauth.Presets, mechanism template) makes one registered
-- client per resource and preset: applying it again returns that client.
CREATE UNIQUE INDEX oauth_clients_preset ON oauth_clients USING btree (environment_id, application_id, resource_id, preset)
    WHERE ((preset <> ''::text) AND (source = 'registered'::text));
