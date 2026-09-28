-- A password someone else chose (IAMKIT_BOOTSTRAP_PASSWORD sits in plaintext in
-- compose files and CI): the first sign-in must replace it.
ALTER TABLE operators ADD COLUMN password_must_change boolean NOT NULL DEFAULT false;

-- How and when a console session signed in: password changes need a recent
-- sign-in, and removing emergency access ends only password sessions.
-- Sessions from before this migration count as old password sessions.
ALTER TABLE operator_sessions
  ADD COLUMN method text NOT NULL DEFAULT 'password' CHECK (method IN ('password','sso')),
  ADD COLUMN authenticated_at timestamptz NOT NULL DEFAULT 'epoch';
ALTER TABLE operator_sessions ALTER COLUMN method DROP DEFAULT;
ALTER TABLE operator_sessions ALTER COLUMN authenticated_at DROP DEFAULT;
