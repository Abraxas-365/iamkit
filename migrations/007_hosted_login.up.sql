-- Hosted login: IAMKit-rendered sign-in pages for OAuth clients that opt in.
--
-- A hosted client's /oauth/authorize redirects the browser to /hosted/login
-- instead of returning the headless JSON ticket. The pages authenticate the
-- user first (password, email code or SSO), then choose the organization,
-- then issue the session and finish the authorization. hosted_logins keeps
-- the verified user between those steps, keyed by the authorization ticket
-- (itself bound to the browser by the __Host-iamkit-authorization cookie).
ALTER TABLE oauth_clients
  ADD COLUMN hosted_login boolean NOT NULL DEFAULT false;

CREATE TABLE hosted_logins (
  ticket_hash     bytea       PRIMARY KEY,
  environment_id  uuid        NOT NULL,
  user_id         uuid        NOT NULL,
  -- The address the user signed in with; the organization step re-checks
  -- SSO enforcement for it.
  email           text        NOT NULL,
  method          text        NOT NULL CHECK (method IN ('password','code','sso')),
  -- Set when the method already fixes the organization (organization SSO).
  organization_id uuid,
  expires_at      timestamptz NOT NULL,
  FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id)
);

-- Environment connections (Google, Microsoft, …) started from the hosted
-- page do not know the organization yet: it is chosen after the callback.
-- continuation holds the authorization ticket the callback resumes; the
-- state is single-use and expires after five minutes, before the ticket. Headless starts always carry organization_id.
ALTER TABLE federation_states
  ALTER COLUMN organization_id DROP NOT NULL,
  ADD COLUMN continuation text,
  ADD CHECK (organization_id IS NOT NULL OR continuation IS NOT NULL);

-- Per-environment branding of the hosted pages.
CREATE TABLE login_settings (
  environment_id uuid PRIMARY KEY REFERENCES environments(id),
  display_name   text NOT NULL DEFAULT '',
  logo_url       text NOT NULL DEFAULT '',
  accent_color   text NOT NULL DEFAULT '' CHECK (accent_color = '' OR accent_color ~ '^#[0-9a-f]{6}$'),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
