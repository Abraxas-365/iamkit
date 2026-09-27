-- 009: delivery activity. One row per environment with the outcome of the
-- latest email delivery attempt and, kept across later successes, of the
-- latest failure, so the console can show whether mail actually goes out.
-- Only fixed, secret-free descriptions are stored: never codes, tokens,
-- webhook URLs or response bodies.
CREATE TABLE delivery_activity (
  environment_id  uuid        PRIMARY KEY REFERENCES environments(id),
  source          text        NOT NULL CHECK (source IN ('environment','global','none')),
  purpose         text        NOT NULL CHECK (purpose IN ('login','password_reset','email_verification','invitation','test')),
  delivered       boolean     NOT NULL,
  status          int         CHECK (status BETWEEN 100 AND 599),
  reason          text        NOT NULL DEFAULT '' CHECK (length(reason) <= 200),
  latency_ms      int         NOT NULL CHECK (latency_ms >= 0),
  attempted_at    timestamptz NOT NULL,
  failure_source  text        CHECK (failure_source IN ('environment','global','none')),
  failure_purpose text        CHECK (failure_purpose IN ('login','password_reset','email_verification','invitation','test')),
  failure_status  int         CHECK (failure_status BETWEEN 100 AND 599),
  failure_reason  text        CHECK (length(failure_reason) <= 200),
  failed_at       timestamptz,
  CHECK ((failed_at IS NULL) = (failure_purpose IS NULL) AND (failed_at IS NULL) = (failure_source IS NULL)),
  CHECK (delivered OR failed_at = attempted_at)
);
