ALTER TABLE sessions ADD COLUMN authenticated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE oauth_authorizations ADD COLUMN requested_at timestamptz NOT NULL DEFAULT now();
