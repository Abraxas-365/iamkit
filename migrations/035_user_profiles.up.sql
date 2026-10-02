-- Custom user data. `metadata` stays free-form operator data; `profile`
-- holds end-user attributes checked against the environment's JSON Schema
-- (user_schemas), some of them self-editable or released as claims.
ALTER TABLE users ADD COLUMN profile jsonb NOT NULL DEFAULT '{}'
  CHECK (jsonb_typeof(profile) = 'object');

CREATE TABLE user_schemas (
  environment_id uuid        PRIMARY KEY REFERENCES environments(id) ON DELETE CASCADE,
  schema         jsonb       NOT NULL CHECK (jsonb_typeof(schema) = 'object'),
  version        int         NOT NULL DEFAULT 1,
  updated_at     timestamptz NOT NULL DEFAULT now()
);
