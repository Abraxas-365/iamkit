-- Organization domains: DNS names an organization claims. A domain is
-- verified on demand (DNS TXT record) or force-verified by an operator; there
-- is no background re-check. A domain belongs to at most one organization per
-- environment, including while unverified (operators resolve disputes).
CREATE TABLE organization_domains (
  id                  uuid        PRIMARY KEY,
  environment_id      uuid        NOT NULL,
  organization_id     uuid        NOT NULL,
  domain              text        NOT NULL CHECK (domain = lower(trim(domain)) AND length(domain) BETWEEN 3 AND 253),
  verification_token  text        NOT NULL,
  verified_at         timestamptz,
  verified_by         text,
  verification_method text        CHECK (verification_method IN ('dns','manual')),
  created_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (environment_id, domain),
  CHECK ((verified_at IS NULL) = (verification_method IS NULL)),
  FOREIGN KEY (organization_id, environment_id)
    REFERENCES organizations(id, environment_id)
);
CREATE INDEX organization_domains_org ON organization_domains(environment_id, organization_id);

-- SCIM adoption can be restricted to emails on the organization's verified
-- domains ('verified_domains'); 'any' keeps the previous behaviour.
ALTER TABLE provisioning_connections
  ADD COLUMN adopt_scope text NOT NULL DEFAULT 'any'
    CHECK (adopt_scope IN ('any','verified_domains'));
