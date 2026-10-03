-- 058: The session inventory lists sessions newest first (F-041).
--
-- Session ids are random UUIDs, so ordering by id gave an arbitrary page:
-- the latest sign-in could be anywhere in a large inventory. authenticated_at
-- cannot order them either (whole seconds, matching auth_time; exchanged
-- child sessions copy their root's). created_at records when the row was
-- written; existing rows take their sign-in time.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS created_at timestamptz;
UPDATE sessions SET created_at = authenticated_at WHERE created_at IS NULL;
ALTER TABLE sessions ALTER COLUMN created_at SET DEFAULT clock_timestamp();
ALTER TABLE sessions ALTER COLUMN created_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS sessions_newest ON sessions (environment_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS sessions_user_newest ON sessions (environment_id, user_id, created_at DESC, id DESC);
DROP INDEX IF EXISTS sessions_user;
