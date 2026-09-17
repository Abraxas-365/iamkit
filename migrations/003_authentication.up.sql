ALTER TABLE sessions ADD CONSTRAINT sessions_environment UNIQUE(id,environment_id);
CREATE TABLE refresh_tokens (
 secret_hash bytea PRIMARY KEY, session_id uuid NOT NULL, environment_id uuid NOT NULL,
 expires_at timestamptz NOT NULL, used_at timestamptz,
 FOREIGN KEY(session_id,environment_id) REFERENCES sessions(id,environment_id)
);
CREATE TABLE identity_challenges (
 id uuid PRIMARY KEY, environment_id uuid NOT NULL, user_id uuid NOT NULL,
 purpose text NOT NULL CHECK(purpose IN ('login','password_reset','email_verification')),
 secret_hash bytea NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz,
 attempts integer NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(user_id,environment_id) REFERENCES users(id,environment_id)
);
CREATE INDEX challenge_user ON identity_challenges(environment_id,user_id,purpose,created_at);
