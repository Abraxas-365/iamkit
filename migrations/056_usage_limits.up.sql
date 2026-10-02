-- 056: Usage limits and daily usage (O2).
--
-- environment_limits holds an environment's own limits; NULL leaves the
-- limit to the deployment (IAMKIT_LIMITS), whose caps an environment can
-- only tighten. usage_daily counts metrics per UTC day: sign-ins and
-- created users are rolled up from the event log by the usage_rollup job
-- (cursor in usage_rollup_cursor), the rest is added by each replica from
-- its in-memory counters.
CREATE TABLE environment_limits (
  environment_id          uuid        PRIMARY KEY REFERENCES environments(id) ON DELETE CASCADE,
  users_max               bigint      CHECK (users_max >= 0),
  organizations_max       bigint      CHECK (organizations_max >= 0),
  applications_max        bigint      CHECK (applications_max >= 0),
  requests_per_minute     bigint      CHECK (requests_per_minute >= 0),
  emails_per_day          bigint      CHECK (emails_per_day >= 0),
  sms_per_day             bigint      CHECK (sms_per_day >= 0),
  action_calls_per_minute bigint      CHECK (action_calls_per_minute >= 0),
  updated_at              timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE usage_daily (
  environment_id uuid   NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  day            date   NOT NULL,
  metric         text   NOT NULL CHECK (metric ~ '^[a-z][a-z_]{0,31}$'),
  count          bigint NOT NULL DEFAULT 0 CHECK (count >= 0),
  PRIMARY KEY (environment_id, day, metric)
);
CREATE INDEX usage_daily_day ON usage_daily (day);

-- One row: the id of the last event rolled up. Starts at the newest event
-- so an upgrade does not count history twice or all at once.
CREATE TABLE usage_rollup_cursor (
  id       boolean PRIMARY KEY DEFAULT true CHECK (id),
  event_id bigint  NOT NULL
);
INSERT INTO usage_rollup_cursor (event_id) SELECT coalesce(max(id), 0) FROM events;

-- Totals are counted per environment on every create.
CREATE INDEX IF NOT EXISTS organizations_environment ON organizations (environment_id);
CREATE INDEX IF NOT EXISTS applications_environment ON applications (environment_id);

-- iam:usage:read opens usage reports to /api/v1.
UPDATE resources SET permissions = permissions || ARRAY['iam:usage:read']
WHERE prefix = 'iam' AND NOT 'iam:usage:read' = ANY(permissions);
