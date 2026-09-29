-- IAMKit as a SAML 2.0 identity provider for applications.
--
-- A service provider (an application that speaks SAML, e.g. a SaaS tool)
-- is registered per environment with its entity ID and assertion consumer
-- service URLs. It signs users in to one application/resource pair, like
-- an OAuth client, and receives the email or the user ID as NameID plus
-- the mapped attributes.
CREATE TABLE saml_service_providers (
  id             uuid        PRIMARY KEY,
  environment_id uuid        NOT NULL,
  application_id uuid        NOT NULL,
  resource_id    uuid        NOT NULL,
  name           text        NOT NULL,
  entity_id      text        NOT NULL,
  acs_urls       text[]      NOT NULL CHECK (cardinality(acs_urls) > 0),
  name_id_format text        NOT NULL DEFAULT 'email' CHECK (name_id_format IN ('email','persistent')),
  -- SAML attribute name → source (email, name, user_id, organization_id,
  -- permissions).
  attributes     jsonb       NOT NULL DEFAULT '{}',
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, environment_id),
  UNIQUE (environment_id, entity_id),
  -- Deleting the provider is required before unlinking the resource.
  FOREIGN KEY (environment_id, application_id, resource_id)
    REFERENCES application_resources(environment_id, application_id, resource_id)
);

-- An AuthnRequest waiting for the hosted sign-in: keyed by the hash of the
-- ik_samlreq_ ticket the hosted pages carry, bound to the browser like an
-- OAuth authorization ticket, answered once.
CREATE TABLE saml_sso_requests (
  ticket_hash         bytea       PRIMARY KEY,
  binding_hash        bytea       NOT NULL,
  environment_id      uuid        NOT NULL,
  service_provider_id uuid        NOT NULL,
  request_id          text        NOT NULL,
  acs_url             text        NOT NULL,
  relay_state         text        NOT NULL DEFAULT '',
  expires_at          timestamptz NOT NULL,
  consumed_at         timestamptz,
  FOREIGN KEY (service_provider_id, environment_id) REFERENCES saml_service_providers(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX saml_sso_requests_expires ON saml_sso_requests(expires_at);
