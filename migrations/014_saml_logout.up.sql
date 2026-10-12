-- SAML single logout (SLO), both directions. Everything here is opt-in:
-- a SAML connection logs out through its identity provider only with
-- options.single_logout, and a SAML application takes part only once it
-- registered slo_url / slo_soap_url and a certificate.

-- ─── IAMKit as service provider (organization SAML connections) ────────
-- The identity provider's view of a session opened by a SAML sign-in: who
-- the assertion named (NameID, its format) and its SessionIndex. An IdP
-- LogoutRequest ends the sessions matching connection + NameID (+ the
-- SessionIndex when it sends one); an SP-initiated logout names them back.
CREATE TABLE federation_sessions (
    session_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    name_id text NOT NULL,
    name_id_format text DEFAULT ''::text NOT NULL,
    session_index text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_sessions_pkey PRIMARY KEY (session_id),
    CONSTRAINT federation_sessions_name_id_check CHECK (((length(name_id) >= 1) AND (length(name_id) <= 1024))),
    CONSTRAINT federation_sessions_session_index_check CHECK ((length(session_index) <= 1024)),
    CONSTRAINT federation_sessions_session_id_fkey FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    CONSTRAINT federation_sessions_connection_id_environment_id_fkey FOREIGN KEY (connection_id, environment_id) REFERENCES federation_connections(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX federation_sessions_subject ON federation_sessions USING btree (connection_id, name_id);

-- The SAML session link travels with a login that waits for a second
-- factor, a hosted page or a custom sign-in UI redeeming its result
-- (authentication.FederationLink as JSON; NULL for every other login).
ALTER TABLE mfa_logins ADD COLUMN federation jsonb;
ALTER TABLE hosted_logins ADD COLUMN federation jsonb;
ALTER TABLE federation_results ADD COLUMN federation jsonb;

-- An SP-initiated logout waiting for the identity provider's
-- LogoutResponse: request_id is the LogoutRequest ID it must answer
-- (InResponseTo); redirect is where the browser goes afterwards ('' = the
-- signed-out page). One use, short-lived (config.SAMLLogoutTTL).
CREATE TABLE saml_logouts (
    request_id text NOT NULL,
    environment_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    redirect text DEFAULT ''::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT saml_logouts_pkey PRIMARY KEY (request_id),
    CONSTRAINT saml_logouts_connection_id_environment_id_fkey FOREIGN KEY (connection_id, environment_id) REFERENCES federation_connections(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX saml_logouts_expires ON saml_logouts USING btree (expires_at);

-- ─── IAMKit as identity provider (SAML applications) ──────────────────
-- slo_url + slo_binding: where IAMKit answers an application's own
-- (browser) LogoutRequest. slo_soap_url: where IAMKit sends a
-- LogoutRequest (SOAP, back-channel) when it ends a session the
-- application received an assertion for. certificate: the application's
-- signing certificate (PEM); its LogoutRequests must be signed with it.
ALTER TABLE saml_service_providers
    ADD COLUMN slo_url text DEFAULT ''::text NOT NULL,
    ADD COLUMN slo_binding text DEFAULT 'redirect'::text NOT NULL,
    ADD COLUMN slo_soap_url text DEFAULT ''::text NOT NULL,
    ADD COLUMN certificate text DEFAULT ''::text NOT NULL,
    ADD CONSTRAINT saml_service_providers_slo_binding_check CHECK ((slo_binding = ANY (ARRAY['redirect'::text, 'post'::text])));

-- Which application received an assertion for which session (and the
-- NameID it carried). No foreign key to sessions: the logout trigger reads
-- these rows when a session row is deleted; saml_idp_session_prune drops
-- rows whose session is gone or ended.
CREATE TABLE saml_idp_sessions (
    session_id uuid NOT NULL,
    service_provider_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    name_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT saml_idp_sessions_pkey PRIMARY KEY (session_id, service_provider_id),
    CONSTRAINT saml_idp_sessions_provider_fkey FOREIGN KEY (service_provider_id, environment_id) REFERENCES saml_service_providers(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX saml_idp_sessions_created ON saml_idp_sessions USING btree (created_at);

-- Back-channel (SOAP) logout outbox, filled by trigger when a session that
-- reached a SAML application with slo_soap_url ends.
CREATE TABLE saml_logout_notifications (
    id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
    environment_id uuid NOT NULL,
    service_provider_id uuid NOT NULL,
    session_id uuid NOT NULL,
    name_id text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    delivered_at timestamp with time zone,
    failed_at timestamp with time zone,
    last_error text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT saml_logout_notifications_pkey PRIMARY KEY (id),
    CONSTRAINT saml_logout_notifications_provider_fkey FOREIGN KEY (service_provider_id, environment_id) REFERENCES saml_service_providers(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX saml_logout_notifications_due ON saml_logout_notifications USING btree (next_attempt_at) WHERE ((delivered_at IS NULL) AND (failed_at IS NULL));

CREATE FUNCTION queue_saml_logout_notification() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  s sessions%ROWTYPE;
BEGIN
  IF TG_OP = 'DELETE' THEN
    s := OLD;
  ELSE
    s := NEW;
  END IF;
  IF OLD.revoked_at IS NOT NULL OR s.expires_at <= now() THEN
    RETURN NULL;
  END IF;
  -- A session replaced by its copy (organization switch: the copy keeps
  -- the links) is no logout (iamkit.saml_logout_skip = 'on').
  IF current_setting('iamkit.saml_logout_skip', true) = 'on' THEN
    RETURN NULL;
  END IF;
  -- The application that asked for this logout itself is not told again
  -- (iamkit.saml_logout_origin = its service provider id).
  INSERT INTO saml_logout_notifications (environment_id, service_provider_id, session_id, name_id)
    SELECT l.environment_id, l.service_provider_id, l.session_id, l.name_id
    FROM saml_idp_sessions l
    JOIN saml_service_providers p ON p.id = l.service_provider_id AND p.environment_id = l.environment_id
    WHERE l.session_id = s.id AND p.slo_soap_url <> ''
      AND l.service_provider_id::text IS DISTINCT FROM nullif(current_setting('iamkit.saml_logout_origin', true), '');
  RETURN NULL;
END $$;

CREATE TRIGGER session_saml_deleted AFTER DELETE ON sessions
  FOR EACH ROW
  EXECUTE FUNCTION queue_saml_logout_notification();
CREATE TRIGGER session_saml_ended AFTER UPDATE OF revoked_at ON sessions
  FOR EACH ROW WHEN (((old.revoked_at IS NULL) AND (new.revoked_at IS NOT NULL)))
  EXECUTE FUNCTION queue_saml_logout_notification();

-- session.revoked carries data.reason when the revoking transaction names
-- one (transaction-local iamkit.session_reason, e.g. saml_logout); a
-- superset of migration 013's data.
CREATE OR REPLACE FUNCTION session_event() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  s sessions%ROWTYPE;
  kind text := 'user';
  actor text;
  t text;
  revoker text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    s := NEW;
    t := 'session.created';
  ELSIF TG_OP = 'DELETE' THEN
    s := OLD;
    IF OLD.revoked_at IS NOT NULL OR OLD.expires_at <= now() THEN
      RETURN NULL;
    END IF;
    t := 'session.revoked';
  ELSE
    s := NEW;
    t := 'session.revoked';
  END IF;
  actor := s.user_id::text;
  revoker := nullif(current_setting('iamkit.session_actor', true), '');
  IF t = 'session.revoked' AND revoker IS NOT NULL AND TG_OP = 'UPDATE' THEN
    actor := revoker;
  ELSIF s.actor_id IS NOT NULL THEN
    kind := 'operator';
    actor := s.actor_id::text;
  ELSIF s.actor_account_id IS NOT NULL THEN
    kind := 'service_account';
    actor := s.actor_account_id::text;
  ELSIF t = 'session.revoked' THEN
    kind := 'system';
    actor := '';
  END IF;
  INSERT INTO events (environment_id, type, actor_kind, actor_id, subject_kind, subject_id, organization_id, data)
  SELECT s.environment_id, t, kind, actor, 'session', s.id::text, s.organization_id,
    jsonb_strip_nulls(jsonb_build_object(
      'user_id', s.user_id, 'organization_id', s.organization_id,
      'application_id', s.application_id, 'resource_id', s.resource_id,
      'oauth_client_id', s.oauth_client_id, 'amr', to_jsonb(s.amr),
      'impersonated', s.actor_id IS NOT NULL OR s.actor_account_id IS NOT NULL,
      'parent_session_id', s.parent_session_id,
      'expires_at', CASE WHEN t = 'session.created' THEN s.expires_at END,
      'ip', CASE WHEN t = 'session.created' THEN host(s.ip_address) END,
      'user_agent', CASE WHEN t = 'session.created' THEN s.user_agent END,
      'country', CASE WHEN t = 'session.created' THEN s.country END,
      'risk_detections', CASE WHEN t = 'session.created' AND cardinality(s.risk_detections) > 0 THEN to_jsonb(s.risk_detections) END,
      'reason', CASE WHEN t = 'session.revoked' THEN nullif(current_setting('iamkit.session_reason', true), '') END))
  WHERE EXISTS (SELECT 1 FROM environments WHERE id = s.environment_id);
  RETURN NULL;
END $$;
