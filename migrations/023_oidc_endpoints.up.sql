-- 023: standard OpenID Connect endpoints (userinfo, introspection,
-- RP-initiated logout).
--
-- post_logout_redirect_uris are where /oauth/end_session may send the
-- browser back after signing out (exact match, like redirect_uris).
ALTER TABLE oauth_clients
  ADD COLUMN post_logout_redirect_uris text[] NOT NULL DEFAULT '{}';

-- The OAuth client an authorization completed a session with; NULL for
-- sessions no OAuth client used (headless logins, older sessions). The
-- first client wins: a session is bound to one client for logout.
ALTER TABLE sessions
  ADD COLUMN oauth_client_id uuid;
