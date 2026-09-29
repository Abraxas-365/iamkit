-- LDAP / Active Directory as organization connections.
--
-- An LDAP connection keeps the normalized directory address as issuer and
-- the lowercased user base DN as client_id (one connection per directory
-- subtree). Its secret is the bind DN's password, sealed; an anonymous
-- search connection (no bind_dn) has none.
ALTER TABLE federation_connections DROP CONSTRAINT federation_connections_provider_check;
ALTER TABLE federation_connections ADD CONSTRAINT federation_connections_provider_check
  CHECK (provider IN ('oidc','google','microsoft','github','apple','gitlab','github_enterprise','oauth2','saml','ldap'));
ALTER TABLE federation_connections DROP CONSTRAINT federation_connections_secret;
ALTER TABLE federation_connections ADD CONSTRAINT federation_connections_secret
  CHECK (CASE WHEN provider = 'saml' THEN secret_env IS NULL AND secret_sealed IS NULL
              WHEN provider = 'ldap' THEN secret_env IS NULL
              ELSE (secret_env IS NULL) <> (secret_sealed IS NULL) END);
ALTER TABLE federation_connections DROP CONSTRAINT federation_connections_saml;
ALTER TABLE federation_connections ADD CONSTRAINT federation_connections_saml
  CHECK (provider NOT IN ('saml','ldap') OR organization_id IS NOT NULL);
