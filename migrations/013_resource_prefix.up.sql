-- Resource prefix: unique scope namespace per environment.
-- Every permission in the resource catalog must start with "{prefix}:".
ALTER TABLE resources ADD COLUMN prefix text;

-- Backfill: derive prefix from audience (last path segment or hostname).
UPDATE resources SET prefix = COALESCE(
  NULLIF(regexp_replace(audience, '^.*/([^/]+)/?$', '\1'), audience),
  regexp_replace(audience, '^https?://([^/:]+).*$', '\1')
);

ALTER TABLE resources ALTER COLUMN prefix SET NOT NULL;
ALTER TABLE resources ADD CONSTRAINT resources_prefix_check CHECK (length(trim(prefix)) >= 1 AND prefix ~ '^[a-z][a-z0-9_-]*$');
ALTER TABLE resources ADD CONSTRAINT resources_env_prefix_unique UNIQUE (environment_id, prefix);
