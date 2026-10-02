-- 054: Headless federation back to a custom sign-in UI (L6). A start may
-- name return_to (an origin an OAuth client of the application allows) and
-- an S256 code_challenge; the callback then parks the verified identity
-- under a one-time handle and redirects there, and the UI redeems the
-- handle with the verifier (POST /identity/v1/federation/result), which
-- signs in. No token is stored.
ALTER TABLE federation_states
  ADD COLUMN return_to text,
  ADD COLUMN return_challenge text,
  ADD CHECK ((return_to IS NULL) = (return_challenge IS NULL));

CREATE TABLE federation_results (
  handle_hash      bytea       PRIMARY KEY,
  environment_id   uuid        NOT NULL,
  organization_id  uuid        NOT NULL,
  application_id   uuid        NOT NULL,
  resource_id      uuid        NOT NULL,
  user_id          uuid        NOT NULL,
  email            text        NOT NULL,
  organization_sso boolean     NOT NULL,
  -- no_access: an organization or social connection proved the identity,
  -- so a refused session means missing access (403), not a bad login.
  no_access        boolean     NOT NULL,
  challenge        text        NOT NULL,
  expires_at       timestamptz NOT NULL,
  FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE,
  FOREIGN KEY (environment_id, application_id, resource_id)
    REFERENCES application_resources(environment_id, application_id, resource_id) ON DELETE CASCADE
);
CREATE INDEX federation_results_expires ON federation_results(expires_at);
