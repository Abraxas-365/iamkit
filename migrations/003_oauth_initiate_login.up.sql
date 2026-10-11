-- OIDC third-party initiated login (OIDC Core §4 / WorkOS-style IdP-initiated
-- SSO): the URL of the client's own sign-in endpoint. IAMKit never signs a
-- user in from an unsolicited SAML response; it redirects the browser here
-- with iss, connection_id and organization_id, and the client then starts a
-- normal /oauth/authorize request. Empty: the client takes no such logins.
ALTER TABLE oauth_clients ADD COLUMN initiate_login_uri text DEFAULT ''::text NOT NULL;
