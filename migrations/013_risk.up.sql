-- Bot protection (CAPTCHA) and risk signals. Everything here is off until
-- an operator configures it: without a captcha_configs row no request needs
-- a CAPTCHA, without a risk_policies row every detection is off, without
-- risk_restrictions nothing is blocked. Only sign_in_attempts (and
-- user_devices on success) are written by default; the risk_signals
-- feature flag turns that off too.

-- One CAPTCHA provider per environment. secret_sealed is sealed with
-- IAMKIT_ENCRYPTION_KEY and never returned. hosted / headless choose where
-- it is required; hostnames are extra hostnames a headless token may have
-- been solved on (hosted pages check the issuer's host).
CREATE TABLE captcha_configs (
    environment_id uuid NOT NULL,
    provider text NOT NULL,
    site_key text NOT NULL,
    secret_sealed text NOT NULL,
    hosted boolean DEFAULT true NOT NULL,
    headless boolean DEFAULT true NOT NULL,
    hostnames text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT captcha_configs_pkey PRIMARY KEY (environment_id),
    CONSTRAINT captcha_configs_provider_check CHECK ((provider = ANY (ARRAY['turnstile'::text, 'hcaptcha'::text]))),
    CONSTRAINT captcha_configs_site_key_check CHECK (((length(site_key) >= 1) AND (length(site_key) <= 200))),
    CONSTRAINT captcha_configs_hostnames_check CHECK ((cardinality(hostnames) <= 20)),
    CONSTRAINT captcha_configs_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);

-- A solved CAPTCHA on a hosted page, bound to the authorization ticket: the
-- next pages of the same journey (password, code, reset, directory) need no
-- second widget until expires_at (config.CaptchaPassTTL) or until
-- uses_left credential posts spent it (config.CaptchaPassUses).
CREATE TABLE hosted_captcha_passes (
    ticket_hash bytea NOT NULL,
    environment_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    uses_left integer NOT NULL,
    CONSTRAINT hosted_captcha_passes_pkey PRIMARY KEY (ticket_hash),
    CONSTRAINT hosted_captcha_passes_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);
CREATE INDEX hosted_captcha_passes_expires ON hosted_captcha_passes USING btree (expires_at);

-- The environment's risk policy. A missing row = every detection off.
-- Actions: off | log | notify | challenge | block (notify only for
-- new_device / stale_account; block not for them).
CREATE TABLE risk_policies (
    environment_id uuid NOT NULL,
    ip_velocity text DEFAULT 'off'::text NOT NULL,
    user_brute_force text DEFAULT 'off'::text NOT NULL,
    impossible_travel text DEFAULT 'off'::text NOT NULL,
    new_device text DEFAULT 'off'::text NOT NULL,
    stale_account text DEFAULT 'off'::text NOT NULL,
    ip_failures_per_hour integer DEFAULT 20 NOT NULL,
    ip_distinct_logins_per_hour integer DEFAULT 10 NOT NULL,
    user_failures_per_hour integer DEFAULT 10 NOT NULL,
    stale_after_days integer DEFAULT 60 NOT NULL,
    travel_speed_kmh integer DEFAULT 1000 NOT NULL,
    notify_user boolean DEFAULT true NOT NULL,
    block_if_unverifiable boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT risk_policies_pkey PRIMARY KEY (environment_id),
    CONSTRAINT risk_policies_ip_velocity_check CHECK ((ip_velocity = ANY (ARRAY['off'::text, 'log'::text, 'challenge'::text, 'block'::text]))),
    CONSTRAINT risk_policies_user_brute_force_check CHECK ((user_brute_force = ANY (ARRAY['off'::text, 'log'::text, 'challenge'::text, 'block'::text]))),
    CONSTRAINT risk_policies_impossible_travel_check CHECK ((impossible_travel = ANY (ARRAY['off'::text, 'log'::text, 'challenge'::text, 'block'::text]))),
    CONSTRAINT risk_policies_new_device_check CHECK ((new_device = ANY (ARRAY['off'::text, 'log'::text, 'notify'::text, 'challenge'::text]))),
    CONSTRAINT risk_policies_stale_account_check CHECK ((stale_account = ANY (ARRAY['off'::text, 'log'::text, 'notify'::text, 'challenge'::text]))),
    CONSTRAINT risk_policies_ip_failures_check CHECK (((ip_failures_per_hour >= 1) AND (ip_failures_per_hour <= 10000))),
    CONSTRAINT risk_policies_ip_logins_check CHECK (((ip_distinct_logins_per_hour >= 1) AND (ip_distinct_logins_per_hour <= 10000))),
    CONSTRAINT risk_policies_user_failures_check CHECK (((user_failures_per_hour >= 1) AND (user_failures_per_hour <= 1000))),
    CONSTRAINT risk_policies_stale_check CHECK (((stale_after_days >= 7) AND (stale_after_days <= 3650))),
    CONSTRAINT risk_policies_travel_check CHECK (((travel_speed_kmh >= 100) AND (travel_speed_kmh <= 20000))),
    CONSTRAINT risk_policies_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);

-- Allow / deny lists checked before any credential. kind ip = a CIDR (a
-- single address is stored as /32 or /128), country = ISO 3166-1 alpha-2
-- (needs GeoIP), email_domain = a lowercase domain (and its subdomains).
CREATE TABLE risk_restrictions (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    kind text NOT NULL,
    value text NOT NULL,
    action text NOT NULL,
    note text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT risk_restrictions_pkey PRIMARY KEY (id),
    CONSTRAINT risk_restrictions_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT risk_restrictions_unique UNIQUE (environment_id, kind, value),
    CONSTRAINT risk_restrictions_kind_check CHECK ((kind = ANY (ARRAY['ip'::text, 'country'::text, 'email_domain'::text]))),
    CONSTRAINT risk_restrictions_action_check CHECK ((action = ANY (ARRAY['allow'::text, 'deny'::text]))),
    CONSTRAINT risk_restrictions_value_check CHECK (((length(value) >= 1) AND (length(value) <= 253))),
    CONSTRAINT risk_restrictions_note_check CHECK ((length(note) <= 200)),
    CONSTRAINT risk_restrictions_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);

-- Every sign-in attempt (hosted and headless, any method), kept
-- IAMKIT_SIGN_IN_ATTEMPT_RETENTION (default 30 days, sign_in_attempt_prune).
-- login_hash is an HMAC of the normalized login keyed per environment, so
-- attempts on unknown accounts are counted without storing what was typed.
-- No foreign key on user_id: attempts outlive deleted users until pruned.
CREATE TABLE sign_in_attempts (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    user_id uuid,
    organization_id uuid,
    login_hash bytea,
    ip inet,
    user_agent text,
    country text,
    latitude double precision,
    longitude double precision,
    device_hash bytea,
    method text NOT NULL,
    surface text NOT NULL,
    outcome text NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    detections text[] DEFAULT '{}'::text[] NOT NULL,
    action text DEFAULT 'none'::text NOT NULL,
    captcha text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT sign_in_attempts_pkey PRIMARY KEY (id),
    CONSTRAINT sign_in_attempts_surface_check CHECK ((surface = ANY (ARRAY['hosted'::text, 'headless'::text]))),
    CONSTRAINT sign_in_attempts_outcome_check CHECK ((outcome = ANY (ARRAY['success'::text, 'failure'::text, 'blocked'::text, 'challenged'::text, 'captcha_failed'::text]))),
    CONSTRAINT sign_in_attempts_action_check CHECK ((action = ANY (ARRAY['none'::text, 'log'::text, 'notify'::text, 'challenge'::text, 'block'::text]))),
    CONSTRAINT sign_in_attempts_captcha_check CHECK ((captcha = ANY (ARRAY[''::text, 'passed'::text, 'failed'::text, 'unavailable'::text]))),
    CONSTRAINT sign_in_attempts_user_agent_length CHECK (((user_agent IS NULL) OR (char_length(user_agent) <= 512))),
    CONSTRAINT sign_in_attempts_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);
CREATE INDEX sign_in_attempts_list ON sign_in_attempts USING btree (environment_id, created_at DESC, id DESC);
CREATE INDEX sign_in_attempts_ip ON sign_in_attempts USING btree (environment_id, ip, created_at);
CREATE INDEX sign_in_attempts_login ON sign_in_attempts USING btree (environment_id, login_hash, created_at);
CREATE INDEX sign_in_attempts_user ON sign_in_attempts USING btree (environment_id, user_id, created_at);
CREATE INDEX sign_in_attempts_created ON sign_in_attempts USING btree (created_at);

-- Devices a user signed in from successfully (hosted cookie
-- __Host-iamkit-device, or the device_id a headless client sends); at most
-- config.MaxUserDevices per user, the least recently seen evicted.
CREATE TABLE user_devices (
    environment_id uuid NOT NULL,
    user_id uuid NOT NULL,
    device_hash bytea NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_ip inet,
    last_country text,
    user_agent text,
    CONSTRAINT user_devices_pkey PRIMARY KEY (environment_id, user_id, device_hash),
    CONSTRAINT user_devices_user_agent_length CHECK (((user_agent IS NULL) OR (char_length(user_agent) <= 512))),
    CONSTRAINT user_devices_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX user_devices_seen ON user_devices USING btree (environment_id, user_id, last_seen_at);
CREATE INDEX user_devices_last_seen ON user_devices USING btree (last_seen_at);

-- A pending login that waits for a risk challenge (an emailed code to the
-- user's verified address) rather than a second factor; risk_detections
-- are what the assessment found, carried to the session it opens.
ALTER TABLE mfa_logins
    ADD COLUMN challenge boolean DEFAULT false NOT NULL,
    ADD COLUMN risk_detections text[] DEFAULT '{}'::text[] NOT NULL;
ALTER TABLE hosted_logins
    ADD COLUMN risk_challenge boolean DEFAULT false NOT NULL,
    ADD COLUMN risk_detections text[] DEFAULT '{}'::text[] NOT NULL;

-- What risk evaluation saw when the session was opened (for
-- session.created and the session inventory).
ALTER TABLE sessions
    ADD COLUMN country text,
    ADD COLUMN risk_detections text[] DEFAULT '{}'::text[] NOT NULL;

-- New IAM resource permissions: iam:security:read / :write (CAPTCHA, risk
-- policy, restrictions, sign-in attempts). No role or service account gains
-- them.
UPDATE resources
   SET permissions = permissions || ARRAY(
         SELECT p FROM unnest(ARRAY['iam:security:read', 'iam:security:write']) AS p
          WHERE NOT (p = ANY (permissions)))
 WHERE prefix = 'iam';

-- session.created carries where the session was opened from and what risk
-- evaluation detected (a superset of migration 006's data).
CREATE OR REPLACE FUNCTION session_event() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  s sessions%ROWTYPE;
  kind text := 'user';
  actor text;
  t text;
  revoker text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    s := NEW;
    t := 'session.created';
  ELSIF TG_OP = 'DELETE' THEN
    s := OLD;
    IF OLD.revoked_at IS NOT NULL OR OLD.expires_at <= now() THEN
      RETURN NULL;
    END IF;
    t := 'session.revoked';
  ELSE
    s := NEW;
    t := 'session.revoked';
  END IF;
  actor := s.user_id::text;
  revoker := nullif(current_setting('iamkit.session_actor', true), '');
  IF t = 'session.revoked' AND revoker IS NOT NULL AND TG_OP = 'UPDATE' THEN
    actor := revoker;
  ELSIF s.actor_id IS NOT NULL THEN
    kind := 'operator';
    actor := s.actor_id::text;
  ELSIF s.actor_account_id IS NOT NULL THEN
    kind := 'service_account';
    actor := s.actor_account_id::text;
  ELSIF t = 'session.revoked' THEN
    kind := 'system';
    actor := '';
  END IF;
  INSERT INTO events (environment_id, type, actor_kind, actor_id, subject_kind, subject_id, organization_id, data)
  SELECT s.environment_id, t, kind, actor, 'session', s.id::text, s.organization_id,
    jsonb_strip_nulls(jsonb_build_object(
      'user_id', s.user_id, 'organization_id', s.organization_id,
      'application_id', s.application_id, 'resource_id', s.resource_id,
      'oauth_client_id', s.oauth_client_id, 'amr', to_jsonb(s.amr),
      'impersonated', s.actor_id IS NOT NULL OR s.actor_account_id IS NOT NULL,
      'parent_session_id', s.parent_session_id,
      'expires_at', CASE WHEN t = 'session.created' THEN s.expires_at END,
      'ip', CASE WHEN t = 'session.created' THEN host(s.ip_address) END,
      'user_agent', CASE WHEN t = 'session.created' THEN s.user_agent END,
      'country', CASE WHEN t = 'session.created' THEN s.country END,
      'risk_detections', CASE WHEN t = 'session.created' AND cardinality(s.risk_detections) > 0 THEN to_jsonb(s.risk_detections) END))
  WHERE EXISTS (SELECT 1 FROM environments WHERE id = s.environment_id);
  RETURN NULL;
END $$;
