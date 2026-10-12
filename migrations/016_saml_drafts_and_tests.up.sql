-- Per-IdP setup guides (guided SSO wizard).
--
-- SAML draft connections: the service provider's entity ID embeds the
-- connection ID, so an administrator needs the connection before the
-- identity provider's metadata exists. A draft is an inactive SAML
-- connection (no sign-in, discovery or routing uses it: every such query
-- already requires active) whose issuer and client_id are both the SP
-- entity ID until the metadata arrives. A column rather than an option:
-- options are administrator-editable, and a plain flag lets the check
-- below and the prune job rely on it.
ALTER TABLE federation_connections ADD COLUMN draft boolean DEFAULT false NOT NULL;
ALTER TABLE federation_connections
    ADD CONSTRAINT federation_connections_draft CHECK ((NOT draft) OR ((NOT active) AND provider = 'saml'));
CREATE INDEX federation_connections_drafts ON federation_connections USING btree (created_at) WHERE draft;

-- Test connection: a one-time ticket (hash stored) starts an identity
-- provider sign-in in test mode. The state of such a sign-in carries test
-- (and who asked for it): its callback renders a result page and never
-- creates a session, user or link. It has no application, so the
-- application and resource of a state become optional for test states.
CREATE TABLE federation_tests (
    ticket_hash bytea NOT NULL,
    connection_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    actor text DEFAULT ''::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_tests_pkey PRIMARY KEY (ticket_hash),
    CONSTRAINT federation_tests_connection_fkey FOREIGN KEY (connection_id, environment_id) REFERENCES federation_connections(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX federation_tests_expires ON federation_tests USING btree (expires_at);

ALTER TABLE federation_states
    ADD COLUMN test boolean DEFAULT false NOT NULL,
    ADD COLUMN test_actor text DEFAULT ''::text NOT NULL,
    ALTER COLUMN application_id DROP NOT NULL,
    ALTER COLUMN resource_id DROP NOT NULL;
ALTER TABLE federation_states DROP CONSTRAINT federation_states_check;
ALTER TABLE federation_states
    ADD CONSTRAINT federation_states_check CHECK (((organization_id IS NOT NULL) OR (continuation IS NOT NULL) OR (consumed_at IS NOT NULL) OR test)),
    ADD CONSTRAINT federation_states_scope CHECK (test OR (application_id IS NOT NULL AND resource_id IS NOT NULL));

-- Pruning a stale draft must take its (test) states with it.
ALTER TABLE federation_states DROP CONSTRAINT federation_states_connection_id_environment_id_fkey;
ALTER TABLE federation_states
    ADD CONSTRAINT federation_states_connection_id_environment_id_fkey FOREIGN KEY (connection_id, environment_id) REFERENCES federation_connections(id, environment_id) ON DELETE CASCADE;
