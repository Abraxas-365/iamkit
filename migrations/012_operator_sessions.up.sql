ALTER TABLE operators ADD COLUMN password_hash text NOT NULL DEFAULT '';
CREATE TABLE operator_sessions (
 id uuid PRIMARY KEY, workspace_id uuid NOT NULL, operator_id uuid NOT NULL,
 secret_hash bytea NOT NULL UNIQUE, expires_at timestamptz NOT NULL, revoked_at timestamptz,
 FOREIGN KEY(workspace_id,operator_id) REFERENCES workspace_members(workspace_id,operator_id)
);
