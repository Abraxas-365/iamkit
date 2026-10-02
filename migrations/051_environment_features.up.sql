-- 051: Feature flags (E5). IAMKit's own features are registered in code
-- (config.Flags) with a default and a scope; IAMKIT_FEATURES sets
-- deployment values and environment-scoped flags can be overridden here.
-- Rows of flags removed from the registry are ignored.
CREATE TABLE environment_features (
  environment_id uuid        NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  name           text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9_]{0,63}$'),
  enabled        boolean     NOT NULL,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (environment_id, name)
);
