-- 053: Per-client allowed origins (L6). A custom sign-in UI or a browser
-- application served from another origin calls /identity/v1 and the
-- browser-facing /oauth endpoints with CORS; an origin listed by an
-- active client of an active application is allowed there, on top of the
-- deployment-wide CORS_ALLOWED_ORIGINS. Values are lowercased
-- scheme://host[:port] (oauth.ValidateOrigins).
ALTER TABLE oauth_clients ADD COLUMN allowed_origins text[] NOT NULL DEFAULT '{}';
CREATE INDEX oauth_clients_allowed_origins ON oauth_clients USING gin (allowed_origins) WHERE active;
