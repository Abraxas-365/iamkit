-- IAMKit schema. Requires an empty public schema.
--
-- Tables are grouped by area; each table is followed by its indexes and
-- triggers. Row-level triggers keep sessions, challenges, events and
-- logout deliveries consistent in the same transaction as the change.

-- ─── Trigger functions ──────────────────────────────────────────────
-- Remove a deleted action target from every execution.
CREATE FUNCTION action_target_deleted() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  UPDATE action_executions SET target_ids = array_remove(target_ids, OLD.id), updated_at = now()
  WHERE environment_id = OLD.environment_id AND OLD.id = ANY (target_ids) AND cardinality(target_ids) > 1;
  DELETE FROM action_executions
  WHERE environment_id = OLD.environment_id AND target_ids = ARRAY[OLD.id];
  RETURN OLD;
END $$;

-- Resolve the actor kind and organization of an audit row.
CREATE FUNCTION audit_event_context() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE id = NEW.actor_id AND environment_id = NEW.environment_id) THEN
        NEW.actor_kind := 'user';
    ELSIF EXISTS (SELECT 1 FROM service_accounts WHERE id = NEW.actor_id AND environment_id = NEW.environment_id) THEN
        NEW.actor_kind := 'service_account';
    END IF;
    IF NEW.organization_id IS NULL THEN
        NEW.organization_id := substring(NEW.target_id FROM '/organizations/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')::uuid;
    END IF;
    RETURN NEW;
END $$;

-- Token-exchange child sessions end with their parent.
CREATE FUNCTION end_child_sessions() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  UPDATE sessions SET revoked_at = NEW.revoked_at
    WHERE parent_session_id = NEW.id AND revoked_at IS NULL;
  RETURN NULL;
END $$;

-- Grants, roles and service accounts stay inside the resource catalog.
CREATE FUNCTION enforce_permission_catalog() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE catalog text[];
BEGIN
  SELECT permissions INTO catalog
    FROM resources WHERE id = NEW.resource_id AND environment_id = NEW.environment_id FOR SHARE;
  IF catalog IS NULL OR NOT NEW.permissions <@ catalog THEN
    RAISE EXCEPTION 'permissions outside resource catalog' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

-- Resolve events.actor_kind when the writer left it NULL.
CREATE FUNCTION event_actor() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
BEGIN
  IF NEW.actor_kind IS NULL THEN
    IF NEW.actor_id = '' THEN
      NEW.actor_kind := 'system';
    ELSIF NEW.actor_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND EXISTS (SELECT 1 FROM users WHERE id = NEW.actor_id::uuid AND environment_id = NEW.environment_id) THEN
      NEW.actor_kind := 'user';
    ELSIF NEW.actor_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND EXISTS (SELECT 1 FROM service_accounts WHERE id = NEW.actor_id::uuid AND environment_id = NEW.environment_id) THEN
      NEW.actor_kind := 'service_account';
    ELSIF NEW.actor_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND EXISTS (SELECT 1 FROM provisioning_credentials WHERE id = NEW.actor_id::uuid AND environment_id = NEW.environment_id) THEN
      NEW.actor_kind := 'directory';
    ELSE
      NEW.actor_kind := 'operator';
    END IF;
  END IF;
  RETURN NEW;
END $_$;

-- Move the subject's pending changes (see record_changes) into the event data.
CREATE FUNCTION event_changes() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  tbl text;
  key text;
  pending jsonb;
BEGIN
  IF NEW.subject_id = '' OR NEW.data ? 'changes' THEN
    RETURN NEW;
  END IF;
  tbl := CASE NEW.subject_kind
    WHEN 'user' THEN 'users' WHEN 'organization' THEN 'organizations'
    WHEN 'application' THEN 'applications' WHEN 'oauth_client' THEN 'oauth_clients'
    WHEN 'role' THEN 'roles' WHEN 'resource' THEN 'resources' END;
  IF tbl IS NULL THEN
    RETURN NEW;
  END IF;
  pending := nullif(current_setting('iamkit.changes', true), '')::jsonb;
  key := tbl || ':' || NEW.subject_id;
  IF pending IS NULL OR NOT pending ? key THEN
    RETURN NEW;
  END IF;
  NEW.data := NEW.data || jsonb_build_object('changes', pending -> key);
  PERFORM set_config('iamkit.changes', (pending - key)::text, true);
  RETURN NEW;
END $$;

-- Spend emailed challenges when the account changes.
CREATE FUNCTION invalidate_identity_challenges() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  UPDATE identity_challenges SET consumed_at = now()
    WHERE environment_id = OLD.environment_id AND user_id = OLD.id AND consumed_at IS NULL;
  RETURN NEW;
END $$;

-- End sessions when what they depend on changes.
CREATE FUNCTION invalidate_identity_sessions() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_TABLE_NAME = 'users' THEN
    UPDATE sessions SET revoked_at = now()
      WHERE environment_id = OLD.environment_id AND user_id = OLD.id AND revoked_at IS NULL;
  ELSIF TG_TABLE_NAME = 'organizations' THEN
    UPDATE sessions SET revoked_at = now()
      WHERE environment_id = OLD.environment_id AND organization_id = OLD.id AND revoked_at IS NULL;
  ELSIF TG_TABLE_NAME = 'applications' THEN
    UPDATE sessions SET revoked_at = now()
      WHERE environment_id = OLD.environment_id AND application_id = OLD.id AND revoked_at IS NULL;
  ELSIF TG_TABLE_NAME = 'roles' THEN
    UPDATE sessions s SET revoked_at = now()
      FROM role_assignments a
      WHERE a.role_id = OLD.id
        AND s.environment_id = a.environment_id AND s.organization_id = a.organization_id
        AND s.user_id = a.user_id AND s.resource_id = a.resource_id AND s.revoked_at IS NULL;
  ELSIF TG_TABLE_NAME = 'memberships' THEN
    UPDATE sessions SET revoked_at = now()
      WHERE environment_id = OLD.environment_id AND organization_id = OLD.organization_id
        AND user_id = OLD.user_id AND revoked_at IS NULL;
  ELSE
    UPDATE sessions SET revoked_at = now()
      WHERE environment_id = OLD.environment_id AND organization_id = OLD.organization_id
        AND user_id = OLD.user_id AND resource_id = OLD.resource_id AND revoked_at IS NULL;
  END IF;
  RETURN OLD;
END $$;

-- Spend login codes when the OTP policy changes.
CREATE FUNCTION invalidate_otp_challenges() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  UPDATE identity_challenges SET consumed_at = now()
    WHERE user_id = NEW.id AND environment_id = NEW.environment_id
      AND purpose = 'login' AND consumed_at IS NULL;
  RETURN NEW;
END $$;

-- Queue a delivery per matching subscription (active, or disabled for failing so that
-- re-enabling resumes).
CREATE FUNCTION queue_event_deliveries() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  INSERT INTO event_deliveries (subscription_id, environment_id, event_id, event_type)
  SELECT s.id, NEW.environment_id, NEW.id, NEW.type
  FROM event_subscriptions s
  WHERE s.environment_id = NEW.environment_id AND (s.active OR s.disabled_reason = 'failing')
    AND (s.types = '{}' OR NEW.type = ANY (s.types) OR split_part(NEW.type, '.', 1) || '.*' = ANY (s.types));
  RETURN NULL;
END $$;

-- Record before/after values of an UPDATE in the transaction-local setting
-- iamkit.changes ({"column": [old, new]}, at most 100 rows per transaction);
-- event_changes attaches them to the next event about the same subject.
-- Secrets, hashes and bookkeeping columns are never recorded.
CREATE FUNCTION record_changes() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  hidden text[] := ARRAY['id', 'environment_id', 'created_at', 'updated_at', 'version',
    'password_hash', 'secret_hash', 'failed_logins', 'last_signed_in_at', 'password_changed_at', 'jwks'];
  old_row jsonb := to_jsonb(OLD);
  new_row jsonb := to_jsonb(NEW);
  diff jsonb := '{}';
  col text;
  sub text;
  a jsonb;
  b jsonb;
  key text := TG_TABLE_NAME || ':' || NEW.id::text;
  pending jsonb;
  prior jsonb;
  merged jsonb := '{}';
BEGIN
  IF coalesce(nullif(current_setting('iamkit.changes_n', true), ''), '0')::int >= 100 THEN
    RETURN NULL;
  END IF;
  FOR col IN SELECT jsonb_object_keys(new_row) LOOP
    CONTINUE WHEN col = ANY(hidden);
    a := old_row -> col;
    b := new_row -> col;
    CONTINUE WHEN a IS NOT DISTINCT FROM b;
    IF jsonb_typeof(a) = 'object' AND jsonb_typeof(b) = 'object' THEN
      FOR sub IN SELECT k FROM jsonb_object_keys(a) k UNION SELECT k FROM jsonb_object_keys(b) k LOOP
        IF (a -> sub) IS DISTINCT FROM (b -> sub) THEN
          diff := diff || jsonb_build_object(col || '.' || sub, jsonb_build_array(a -> sub, b -> sub));
        END IF;
      END LOOP;
    ELSE
      diff := diff || jsonb_build_object(col, jsonb_build_array(a, b));
    END IF;
  END LOOP;
  IF diff = '{}' THEN
    RETURN NULL;
  END IF;
  pending := coalesce(nullif(current_setting('iamkit.changes', true), ''), '{}')::jsonb;
  prior := pending -> key;
  IF prior IS NOT NULL THEN
    -- Merge: the first old value, the latest new one; drop no-ops.
    FOR col IN SELECT k FROM jsonb_object_keys(prior) k UNION SELECT k FROM jsonb_object_keys(diff) k LOOP
      a := coalesce(prior -> col -> 0, diff -> col -> 0);
      b := coalesce(diff -> col -> 1, prior -> col -> 1);
      IF a IS DISTINCT FROM b THEN
        merged := merged || jsonb_build_object(col, jsonb_build_array(a, b));
      END IF;
    END LOOP;
    diff := merged;
  END IF;
  IF prior IS NULL THEN
    PERFORM set_config('iamkit.changes_n', (coalesce(nullif(current_setting('iamkit.changes_n', true), ''), '0')::int + 1)::text, true);
  END IF;
  PERFORM set_config('iamkit.changes', (pending || jsonb_build_object(key, diff))::text, true);
  RETURN NULL;
END $$;

-- Machine users never get sign-in credentials; raised as a foreign key violation.
CREATE FUNCTION refuse_machine_user() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE id = NEW.user_id AND environment_id = NEW.environment_id AND kind = 'machine') THEN
        RAISE EXCEPTION 'machine users cannot have sign-in credentials' USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END $$;

-- ─── Management plane: workspaces, operators and the console sign-in state ────
CREATE TABLE workspaces (
    id uuid NOT NULL,
    name text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT workspaces_name_check CHECK ((length(TRIM(BOTH FROM name)) > 0)),
    CONSTRAINT workspaces_pkey PRIMARY KEY (id)
);

-- Console operators. A password hash of '' means the operator signs in with SSO only.
CREATE TABLE operators (
    id uuid NOT NULL,
    email text NOT NULL,
    password_hash text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    password_must_change boolean DEFAULT false NOT NULL,
    locale text,
    CONSTRAINT operators_email_check CHECK ((email = lower(TRIM(BOTH FROM email)))),
    CONSTRAINT operators_pkey PRIMARY KEY (id),
    CONSTRAINT operators_email_key UNIQUE (email)
);

CREATE TABLE workspace_members (
    workspace_id uuid NOT NULL,
    operator_id uuid NOT NULL,
    role text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    password_allowed boolean DEFAULT false NOT NULL,
    CONSTRAINT workspace_members_role_check CHECK ((role = ANY (ARRAY['owner'::text, 'admin'::text, 'viewer'::text]))),
    CONSTRAINT workspace_members_pkey PRIMARY KEY (workspace_id, operator_id),
    CONSTRAINT workspace_members_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES operators(id),
    CONSTRAINT workspace_members_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE TABLE management_keys (
    id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    operator_id uuid NOT NULL,
    secret_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT management_keys_pkey PRIMARY KEY (id),
    CONSTRAINT management_keys_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT management_keys_workspace_id_operator_id_fkey FOREIGN KEY (workspace_id, operator_id) REFERENCES workspace_members(workspace_id, operator_id)
);

CREATE TABLE operator_sessions (
    id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    operator_id uuid NOT NULL,
    secret_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    method text NOT NULL,
    authenticated_at timestamp with time zone NOT NULL,
    CONSTRAINT operator_sessions_method_check CHECK ((method = ANY (ARRAY['password'::text, 'sso'::text]))),
    CONSTRAINT operator_sessions_pkey PRIMARY KEY (id),
    CONSTRAINT operator_sessions_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT operator_sessions_workspace_id_operator_id_fkey FOREIGN KEY (workspace_id, operator_id) REFERENCES workspace_members(workspace_id, operator_id)
);

-- Operator single sign-on: providers come from deployment configuration and are
-- never stored. Only the identities linked to operators are. The key is the
-- verified token issuer and subject, so renaming a provider ID keeps the
-- links. Operators are never created here: the first sign-in links to an
-- invited operator by verified email. One identity per issuer per operator.
CREATE TABLE operator_identities (
    issuer text NOT NULL,
    subject text NOT NULL,
    operator_id uuid NOT NULL,
    provider text NOT NULL,
    email text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login_at timestamp with time zone,
    CONSTRAINT operator_identities_issuer_check CHECK (((length(issuer) >= 1) AND (length(issuer) <= 2048))),
    CONSTRAINT operator_identities_subject_check CHECK (((length(subject) >= 1) AND (length(subject) <= 512))),
    CONSTRAINT operator_identities_pkey PRIMARY KEY (issuer, subject),
    CONSTRAINT operator_identities_operator_id_issuer_key UNIQUE (operator_id, issuer),
    CONSTRAINT operator_identities_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES operators(id)
);

-- A started operator sign-in awaiting the provider callback, keyed by the hash of the
-- state parameter and bound to the browser that started it.
CREATE TABLE operator_sso_states (
    secret_hash bytea NOT NULL,
    provider text NOT NULL,
    binding_hash bytea NOT NULL,
    nonce text NOT NULL,
    verifier text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    CONSTRAINT operator_sso_states_pkey PRIMARY KEY (secret_hash)
);
CREATE INDEX operator_sso_states_expires ON operator_sso_states USING btree (expires_at);

CREATE TABLE projects (
    id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    name text NOT NULL,
    CONSTRAINT projects_pkey PRIMARY KEY (id),
    CONSTRAINT projects_id_workspace_id_key UNIQUE (id, workspace_id),
    CONSTRAINT projects_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
);

CREATE TABLE environments (
    id uuid NOT NULL,
    project_id uuid NOT NULL,
    name text NOT NULL,
    CONSTRAINT environments_pkey PRIMARY KEY (id),
    CONSTRAINT environments_project_id_name_key UNIQUE (project_id, name),
    CONSTRAINT environments_project_id_fkey FOREIGN KEY (project_id) REFERENCES projects(id)
);
CREATE INDEX environments_project ON environments USING btree (project_id);

-- ─── Organizations, users and directory structure ──────────────────────
CREATE TABLE organizations (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    name text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    mfa_required boolean DEFAULT false NOT NULL,
    mfa_for_federated boolean DEFAULT false NOT NULL,
    allow_password boolean DEFAULT true NOT NULL,
    allow_email_code boolean DEFAULT true NOT NULL,
    allow_social boolean DEFAULT true NOT NULL,
    allowed_factors text[] DEFAULT '{totp,email,sms,webauthn}'::text[] NOT NULL,
    allow_passkey boolean DEFAULT true NOT NULL,
    CONSTRAINT organizations_allowed_factors_check CHECK ((allowed_factors <@ ARRAY['totp'::text, 'email'::text, 'sms'::text, 'webauthn'::text])),
    CONSTRAINT organizations_pkey PRIMARY KEY (id),
    CONSTRAINT organizations_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT organizations_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id)
);
CREATE INDEX organizations_environment ON organizations USING btree (environment_id);
CREATE TRIGGER organization_changed AFTER UPDATE ON organizations
  FOR EACH ROW WHEN ((old.active IS DISTINCT FROM new.active))
  EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER record_changes AFTER UPDATE ON organizations
  FOR EACH ROW
  EXECUTE FUNCTION record_changes();

CREATE TABLE organization_domains (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    domain text NOT NULL,
    verification_token text NOT NULL,
    verified_at timestamp with time zone,
    verified_by text,
    verification_method text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_domains_check CHECK (((verified_at IS NULL) = (verification_method IS NULL))),
    CONSTRAINT organization_domains_domain_check CHECK (((domain = lower(TRIM(BOTH FROM domain))) AND ((length(domain) >= 3) AND (length(domain) <= 253)))),
    CONSTRAINT organization_domains_verification_method_check CHECK ((verification_method = ANY (ARRAY['dns'::text, 'manual'::text]))),
    CONSTRAINT organization_domains_pkey PRIMARY KEY (id),
    CONSTRAINT organization_domains_environment_id_domain_key UNIQUE (environment_id, domain),
    CONSTRAINT organization_domains_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id)
);
CREATE INDEX organization_domains_org ON organization_domains USING btree (environment_id, organization_id);

CREATE TABLE organization_login_settings (
    organization_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    display_name text,
    logo_url text,
    accent_color text,
    theme jsonb,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    locale text,
    CONSTRAINT organization_login_settings_accent_color_check CHECK (((accent_color IS NULL) OR (accent_color ~ '^#[0-9a-f]{6}$'::text))),
    CONSTRAINT organization_login_settings_locale_check CHECK (((locale IS NULL) OR ((length(locale) >= 2) AND (length(locale) <= 16)))),
    CONSTRAINT organization_login_settings_pkey PRIMARY KEY (organization_id),
    CONSTRAINT organization_login_settings_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX organization_login_settings_environment ON organization_login_settings USING btree (environment_id);

CREATE TABLE organization_password_policies (
    organization_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    min_length integer NOT NULL,
    require_upper boolean NOT NULL,
    require_lower boolean NOT NULL,
    require_digit boolean NOT NULL,
    require_symbol boolean NOT NULL,
    max_age_days integer NOT NULL,
    breach_check boolean NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_password_policies_max_age_days_check CHECK (((max_age_days >= 0) AND (max_age_days <= 3650))),
    CONSTRAINT organization_password_policies_min_length_check CHECK (((min_length = 0) OR ((min_length >= 8) AND (min_length <= 72)))),
    CONSTRAINT organization_password_policies_pkey PRIMARY KEY (organization_id),
    CONSTRAINT organization_password_policie_organization_id_environment__fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX organization_password_policies_environment ON organization_password_policies USING btree (environment_id);

-- End users. kind 'machine' users have no email, username, password, phone or
-- second factor (CHECK users_kind_credentials) and authenticate only with
-- personal access tokens or keys. username is stored lowercase and never holds
-- '@', so a sign-in input is an email exactly when it has one.
-- home_organization_id: organization administrators edit a user's record only
-- when the user belongs to their organization.
CREATE TABLE users (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    email text,
    name text NOT NULL,
    password_hash text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    email_verified boolean DEFAULT false NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    otp_enabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    failed_logins integer DEFAULT 0 NOT NULL,
    locked_until timestamp with time zone,
    password_changed_at timestamp with time zone DEFAULT now() NOT NULL,
    phone text DEFAULT ''::text NOT NULL,
    phone_verified boolean DEFAULT false NOT NULL,
    last_signed_in_at timestamp with time zone,
    profile jsonb DEFAULT '{}'::jsonb NOT NULL,
    avatar_url text DEFAULT ''::text NOT NULL,
    username text,
    home_organization_id uuid,
    kind text DEFAULT 'human'::text NOT NULL,
    terms_accepted_at timestamp with time zone,
    password_change_required boolean DEFAULT false NOT NULL,
    CONSTRAINT users_avatar_url_check CHECK ((length(avatar_url) <= 2048)),
    CONSTRAINT users_email_check CHECK ((email = lower(TRIM(BOTH FROM email)))),
    CONSTRAINT users_kind_check CHECK ((kind = ANY (ARRAY['human'::text, 'machine'::text]))),
    CONSTRAINT users_kind_credentials CHECK ((((kind = 'human'::text) AND (email IS NOT NULL)) OR ((kind = 'machine'::text) AND (email IS NULL) AND (username IS NULL) AND (password_hash = ''::text) AND (NOT otp_enabled) AND (NOT email_verified) AND (phone = ''::text)))),
    CONSTRAINT users_phone_check CHECK (((phone = ''::text) OR (phone ~ '^\+[1-9][0-9]{6,14}$'::text))),
    CONSTRAINT users_phone_verified CHECK (((phone <> ''::text) OR (NOT phone_verified))),
    CONSTRAINT users_profile_check CHECK ((jsonb_typeof(profile) = 'object'::text)),
    CONSTRAINT users_username_check CHECK (((username = lower(username)) AND (username ~ '^[a-z0-9][a-z0-9._-]{2,63}$'::text))),
    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT users_environment_id_email_key UNIQUE (environment_id, email),
    CONSTRAINT users_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT users_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id),
    CONSTRAINT users_home_organization FOREIGN KEY (home_organization_id, environment_id) REFERENCES organizations(id, environment_id)
);
CREATE UNIQUE INDEX users_environment_username ON users USING btree (environment_id, username) WHERE (username IS NOT NULL);
CREATE TRIGGER challenges_changed AFTER UPDATE ON users
  FOR EACH ROW WHEN ((((old.active IS DISTINCT FROM new.active) OR (old.password_hash IS DISTINCT FROM new.password_hash)) OR (old.email IS DISTINCT FROM new.email)))
  EXECUTE FUNCTION invalidate_identity_challenges();
CREATE TRIGGER otp_policy_changed AFTER UPDATE OF otp_enabled ON users
  FOR EACH ROW WHEN ((old.otp_enabled IS DISTINCT FROM new.otp_enabled))
  EXECUTE FUNCTION invalidate_otp_challenges();
CREATE TRIGGER record_changes AFTER UPDATE ON users
  FOR EACH ROW
  EXECUTE FUNCTION record_changes();
CREATE TRIGGER user_changed AFTER UPDATE ON users
  FOR EACH ROW WHEN ((((old.active IS DISTINCT FROM new.active) OR (old.password_hash IS DISTINCT FROM new.password_hash)) OR (old.email IS DISTINCT FROM new.email)))
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TABLE org_units (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    parent_id uuid,
    name text NOT NULL,
    kind text NOT NULL,
    CONSTRAINT org_units_check CHECK ((parent_id IS DISTINCT FROM id)),
    CONSTRAINT org_units_name_check CHECK ((length(TRIM(BOTH FROM name)) > 0)),
    CONSTRAINT org_units_pkey PRIMARY KEY (id),
    CONSTRAINT org_units_environment_id_organization_id_id_key UNIQUE (environment_id, organization_id, id),
    CONSTRAINT org_units_environment_id_organization_id_parent_id_fkey FOREIGN KEY (environment_id, organization_id, parent_id) REFERENCES org_units(environment_id, organization_id, id),
    CONSTRAINT org_units_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id)
);

-- sso_bypass is the break-glass flag: the member may keep using password and email
-- code sign-in while the organization enforces SSO.
CREATE TABLE memberships (
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    active boolean DEFAULT true NOT NULL,
    org_unit_id uuid,
    manager_id uuid,
    display_name text,
    sso_bypass boolean DEFAULT false NOT NULL,
    CONSTRAINT no_self_manager CHECK ((manager_id IS DISTINCT FROM user_id)),
    CONSTRAINT memberships_pkey PRIMARY KEY (organization_id, user_id),
    CONSTRAINT memberships_environment_id_organization_id_user_id_key UNIQUE (environment_id, organization_id, user_id),
    CONSTRAINT membership_manager FOREIGN KEY (environment_id, organization_id, manager_id) REFERENCES memberships(environment_id, organization_id, user_id),
    CONSTRAINT membership_unit FOREIGN KEY (environment_id, organization_id, org_unit_id) REFERENCES org_units(environment_id, organization_id, id),
    CONSTRAINT memberships_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id),
    CONSTRAINT memberships_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id)
);
CREATE INDEX memberships_user ON memberships USING btree (environment_id, user_id);
CREATE TRIGGER membership_changed AFTER UPDATE ON memberships
  FOR EACH ROW WHEN ((old.active IS DISTINCT FROM new.active))
  EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER membership_removed AFTER DELETE ON memberships
  FOR EACH ROW
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TABLE positions (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    name text NOT NULL,
    code text NOT NULL,
    CONSTRAINT positions_name_check CHECK ((length(TRIM(BOTH FROM name)) > 0)),
    CONSTRAINT positions_pkey PRIMARY KEY (id),
    CONSTRAINT positions_environment_id_organization_id_id_key UNIQUE (environment_id, organization_id, id),
    CONSTRAINT positions_organization_id_code_key UNIQUE (organization_id, code),
    CONSTRAINT positions_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id)
);

CREATE TABLE position_assignments (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    position_id uuid NOT NULL,
    user_id uuid NOT NULL,
    org_unit_id uuid,
    CONSTRAINT position_assignments_pkey PRIMARY KEY (id),
    CONSTRAINT position_assignments_environment_id_organization_id_org_un_fkey FOREIGN KEY (environment_id, organization_id, org_unit_id) REFERENCES org_units(environment_id, organization_id, id),
    CONSTRAINT position_assignments_environment_id_organization_id_positi_fkey FOREIGN KEY (environment_id, organization_id, position_id) REFERENCES positions(environment_id, organization_id, id),
    CONSTRAINT position_assignments_environment_id_organization_id_user_i_fkey FOREIGN KEY (environment_id, organization_id, user_id) REFERENCES memberships(environment_id, organization_id, user_id)
);

-- SCIM provisioning.
CREATE TABLE provisioning_connections (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    name text NOT NULL,
    adopt_existing_members boolean DEFAULT false NOT NULL,
    adopt_scope text DEFAULT 'any'::text NOT NULL,
    map_phone boolean DEFAULT false NOT NULL,
    CONSTRAINT provisioning_connections_adopt_scope_check CHECK ((adopt_scope = ANY (ARRAY['any'::text, 'verified_domains'::text]))),
    CONSTRAINT provisioning_connections_pkey PRIMARY KEY (id),
    CONSTRAINT provisioning_connections_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT provisioning_connections_id_environment_id_organization_id_key UNIQUE (id, environment_id, organization_id),
    CONSTRAINT provisioning_connections_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id)
);

-- connection_id/external_id are set for SCIM-managed groups.
CREATE TABLE groups (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    connection_id uuid,
    external_id text,
    version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT groups_name_check CHECK ((length(TRIM(BOTH FROM name)) > 0)),
    CONSTRAINT groups_pkey PRIMARY KEY (id),
    CONSTRAINT groups_id_environment_id_organization_id_key UNIQUE (id, environment_id, organization_id),
    CONSTRAINT groups_connection_id_environment_id_organization_id_fkey FOREIGN KEY (connection_id, environment_id, organization_id) REFERENCES provisioning_connections(id, environment_id, organization_id),
    CONSTRAINT groups_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id)
);
CREATE UNIQUE INDEX groups_connection_external ON groups USING btree (connection_id, external_id) WHERE (external_id IS NOT NULL);
CREATE UNIQUE INDEX groups_connection_name ON groups USING btree (connection_id, lower(name)) WHERE (connection_id IS NOT NULL);
CREATE UNIQUE INDEX groups_manual_name ON groups USING btree (organization_id, lower(name)) WHERE (connection_id IS NULL);

CREATE TABLE provisioning_credentials (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    name text NOT NULL,
    secret_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT provisioning_credentials_pkey PRIMARY KEY (id),
    CONSTRAINT provisioning_credentials_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT provisioning_credentials_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT provisioning_connection FOREIGN KEY (connection_id, environment_id, organization_id) REFERENCES provisioning_connections(id, environment_id, organization_id),
    CONSTRAINT provisioning_credentials_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id)
);

CREATE TABLE provisioned_identities (
    connection_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    user_id uuid NOT NULL,
    external_id text NOT NULL,
    external_id_source text DEFAULT 'client'::text NOT NULL,
    deprovisioned_at timestamp with time zone,
    version bigint DEFAULT 0 NOT NULL,
    origin text DEFAULT 'linked'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT provisioned_identities_external_id_source_check CHECK ((external_id_source = ANY (ARRAY['client'::text, 'derived'::text]))),
    CONSTRAINT provisioned_identities_origin_check CHECK ((origin = ANY (ARRAY['created'::text, 'adopted'::text, 'linked'::text]))),
    CONSTRAINT provisioned_identities_pkey PRIMARY KEY (connection_id, external_id),
    CONSTRAINT provisioned_identities_connection_id_user_id_key UNIQUE (connection_id, user_id),
    CONSTRAINT provisioned_identities_connection_id_environment_id_fkey FOREIGN KEY (connection_id, environment_id) REFERENCES provisioning_connections(id, environment_id),
    CONSTRAINT provisioned_identities_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id)
);
CREATE TRIGGER provisioned_identities_human BEFORE INSERT ON provisioned_identities
  FOR EACH ROW
  EXECUTE FUNCTION refuse_machine_user();

CREATE TABLE provisioned_emails (
    connection_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    user_id uuid NOT NULL,
    email text NOT NULL,
    type text DEFAULT 'other'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT provisioned_emails_email_check CHECK ((email = lower(TRIM(BOTH FROM email)))),
    CONSTRAINT provisioned_emails_pkey PRIMARY KEY (connection_id, user_id, email),
    CONSTRAINT provisioned_emails_connection_id_user_id_fkey FOREIGN KEY (connection_id, user_id) REFERENCES provisioned_identities(connection_id, user_id) ON DELETE CASCADE,
    CONSTRAINT provisioned_emails_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX provisioned_emails_lookup ON provisioned_emails USING btree (connection_id, email);

-- ─── Applications and authorization ────────────────────────────────────
CREATE TABLE applications (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    name text NOT NULL,
    redirect_uris text[] DEFAULT '{}'::text[] NOT NULL,
    active boolean DEFAULT true NOT NULL,
    CONSTRAINT applications_pkey PRIMARY KEY (id),
    CONSTRAINT applications_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT applications_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id)
);
CREATE INDEX applications_environment ON applications USING btree (environment_id);
CREATE TRIGGER application_changed AFTER UPDATE ON applications
  FOR EACH ROW WHEN ((old.active IS DISTINCT FROM new.active))
  EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER record_changes AFTER UPDATE ON applications
  FOR EACH ROW
  EXECUTE FUNCTION record_changes();

-- A resource may belong to an organization (the vendor that ships it) and be
-- granted to others. With require_grant, token access is limited to the owner
-- and granted organizations. The IAM resource is governed by organization
-- administration and is never owned or granted (resources_iam_unowned).
CREATE TABLE resources (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    name text NOT NULL,
    prefix text NOT NULL,
    audience text NOT NULL,
    permissions text[] DEFAULT '{}'::text[] NOT NULL,
    owner_organization_id uuid,
    require_grant boolean DEFAULT false NOT NULL,
    CONSTRAINT resources_audience_check CHECK ((length(TRIM(BOTH FROM audience)) > 0)),
    CONSTRAINT resources_iam_unowned CHECK (((prefix <> 'iam'::text) OR ((owner_organization_id IS NULL) AND (NOT require_grant)))),
    CONSTRAINT resources_prefix_check CHECK (((length(TRIM(BOTH FROM prefix)) >= 1) AND (prefix ~ '^[a-z][a-z0-9_-]*$'::text))),
    CONSTRAINT resources_pkey PRIMARY KEY (id),
    CONSTRAINT resources_environment_id_audience_key UNIQUE (environment_id, audience),
    CONSTRAINT resources_environment_id_prefix_key UNIQUE (environment_id, prefix),
    CONSTRAINT resources_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT resources_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id),
    CONSTRAINT resources_owner_organization FOREIGN KEY (owner_organization_id, environment_id) REFERENCES organizations(id, environment_id)
);
CREATE TRIGGER record_changes AFTER UPDATE ON resources
  FOR EACH ROW
  EXECUTE FUNCTION record_changes();

CREATE TABLE application_resources (
    environment_id uuid NOT NULL,
    application_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    CONSTRAINT application_resources_pkey PRIMARY KEY (application_id, resource_id),
    CONSTRAINT application_resources_environment_id_application_id_resourc_key UNIQUE (environment_id, application_id, resource_id),
    CONSTRAINT application_resources_application_id_environment_id_fkey FOREIGN KEY (application_id, environment_id) REFERENCES applications(id, environment_id),
    CONSTRAINT application_resources_resource_id_environment_id_fkey FOREIGN KEY (resource_id, environment_id) REFERENCES resources(id, environment_id)
);

-- system_role names the built-in roles of the IAM resource (authorization.SystemRoles): fixed
-- permissions, never edited or deleted, independent of the display name.
CREATE TABLE roles (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    name text NOT NULL,
    permissions text[] DEFAULT '{}'::text[] NOT NULL,
    system_role text,
    CONSTRAINT roles_name_check CHECK ((length(TRIM(BOTH FROM name)) > 0)),
    CONSTRAINT roles_system_role_check CHECK ((system_role = ANY (ARRAY['org_owner'::text, 'org_viewer'::text, 'org_user_manager'::text, 'org_settings_manager'::text, 'org_resource_manager'::text]))),
    CONSTRAINT roles_pkey PRIMARY KEY (id),
    CONSTRAINT roles_environment_id_resource_id_id_key UNIQUE (environment_id, resource_id, id),
    CONSTRAINT roles_resource_id_name_key UNIQUE (resource_id, name),
    CONSTRAINT roles_resource_id_environment_id_fkey FOREIGN KEY (resource_id, environment_id) REFERENCES resources(id, environment_id)
);
CREATE UNIQUE INDEX roles_resource_system_role ON roles USING btree (resource_id, system_role) WHERE (system_role IS NOT NULL);
CREATE TRIGGER record_changes AFTER UPDATE ON roles
  FOR EACH ROW
  EXECUTE FUNCTION record_changes();
CREATE TRIGGER role_catalog BEFORE INSERT OR UPDATE ON roles
  FOR EACH ROW
  EXECUTE FUNCTION enforce_permission_catalog();
CREATE TRIGGER role_deleted BEFORE DELETE ON roles
  FOR EACH ROW
  EXECUTE FUNCTION invalidate_identity_sessions();
CREATE TRIGGER role_updated AFTER UPDATE ON roles
  FOR EACH ROW
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TABLE grants (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    permissions text[] DEFAULT '{}'::text[] NOT NULL,
    CONSTRAINT grants_pkey PRIMARY KEY (id),
    CONSTRAINT grants_organization_id_user_id_resource_id_key UNIQUE (organization_id, user_id, resource_id),
    CONSTRAINT grants_environment_id_organization_id_user_id_fkey FOREIGN KEY (environment_id, organization_id, user_id) REFERENCES memberships(environment_id, organization_id, user_id),
    CONSTRAINT grants_resource_id_environment_id_fkey FOREIGN KEY (resource_id, environment_id) REFERENCES resources(id, environment_id)
);
CREATE TRIGGER grant_catalog BEFORE INSERT OR UPDATE ON grants
  FOR EACH ROW
  EXECUTE FUNCTION enforce_permission_catalog();
CREATE TRIGGER grant_changed AFTER DELETE OR UPDATE ON grants
  FOR EACH ROW
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TABLE role_assignments (
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    role_id uuid NOT NULL,
    CONSTRAINT role_assignments_pkey PRIMARY KEY (organization_id, user_id, role_id),
    CONSTRAINT role_assignments_environment_id_organization_id_user_id_fkey FOREIGN KEY (environment_id, organization_id, user_id) REFERENCES memberships(environment_id, organization_id, user_id),
    CONSTRAINT role_assignments_environment_id_resource_id_role_id_fkey FOREIGN KEY (environment_id, resource_id, role_id) REFERENCES roles(environment_id, resource_id, id) ON DELETE CASCADE
);
CREATE TRIGGER role_assignment_changed AFTER DELETE ON role_assignments
  FOR EACH ROW
  EXECUTE FUNCTION invalidate_identity_sessions();

CREATE TABLE group_members (
    group_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT group_members_pkey PRIMARY KEY (group_id, user_id),
    CONSTRAINT group_members_environment_id_organization_id_user_id_fkey FOREIGN KEY (environment_id, organization_id, user_id) REFERENCES memberships(environment_id, organization_id, user_id) ON DELETE CASCADE,
    CONSTRAINT group_members_group_id_environment_id_organization_id_fkey FOREIGN KEY (group_id, environment_id, organization_id) REFERENCES groups(id, environment_id, organization_id) ON DELETE CASCADE
);
CREATE INDEX group_members_user ON group_members USING btree (organization_id, user_id);

CREATE TABLE group_role_assignments (
    group_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    role_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT group_role_assignments_pkey PRIMARY KEY (group_id, role_id),
    CONSTRAINT group_role_assignments_environment_id_resource_id_role_id_fkey FOREIGN KEY (environment_id, resource_id, role_id) REFERENCES roles(environment_id, resource_id, id) ON DELETE CASCADE,
    CONSTRAINT group_role_assignments_group_id_environment_id_organizatio_fkey FOREIGN KEY (group_id, environment_id, organization_id) REFERENCES groups(id, environment_id, organization_id) ON DELETE CASCADE
);
CREATE INDEX group_role_assignments_role ON group_role_assignments USING btree (role_id);

-- role_ids NULL grants every role of the resource, current and future.
CREATE TABLE resource_grants (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    role_ids uuid[],
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT resource_grants_pkey PRIMARY KEY (id),
    CONSTRAINT resource_grants_resource_id_organization_id_key UNIQUE (resource_id, organization_id),
    CONSTRAINT resource_grants_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE,
    CONSTRAINT resource_grants_resource_id_environment_id_fkey FOREIGN KEY (resource_id, environment_id) REFERENCES resources(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX resource_grants_organization ON resource_grants USING btree (organization_id);

-- What a user may do on a resource: direct grants, assigned roles and roles of
-- groups. For resources with require_grant only the owner organization and
-- granted organizations count (and, for role permissions, only granted roles).
CREATE VIEW effective_grants AS
  SELECT access.environment_id, access.organization_id, access.user_id, access.resource_id,
    COALESCE(array_agg(DISTINCT access.permission)
      FILTER (WHERE access.permission IS NOT NULL), '{}') AS permissions
  FROM (
    SELECT g.environment_id, g.organization_id, g.user_id, g.resource_id, NULL::uuid AS role_id, p.permission
      FROM grants g LEFT JOIN LATERAL unnest(g.permissions) p(permission) ON true
    UNION ALL
    SELECT a.environment_id, a.organization_id, a.user_id, a.resource_id, a.role_id, p.permission
      FROM role_assignments a JOIN roles r ON r.id = a.role_id
      LEFT JOIN LATERAL unnest(r.permissions) p(permission) ON true
    UNION ALL
    SELECT gm.environment_id, gm.organization_id, gm.user_id, ga.resource_id, ga.role_id, p.permission
      FROM group_members gm
      JOIN group_role_assignments ga ON ga.group_id = gm.group_id
      JOIN roles r ON r.id = ga.role_id
      LEFT JOIN LATERAL unnest(r.permissions) p(permission) ON true
  ) access
  JOIN resources res ON res.id = access.resource_id
  WHERE NOT res.require_grant
     OR res.owner_organization_id = access.organization_id
     OR EXISTS (SELECT 1 FROM resource_grants rg
                WHERE rg.resource_id = access.resource_id AND rg.organization_id = access.organization_id
                  AND (access.role_id IS NULL OR rg.role_ids IS NULL OR access.role_id = ANY(rg.role_ids)))
  GROUP BY access.environment_id, access.organization_id, access.user_id, access.resource_id;

-- ─── OAuth clients, device codes and SAML service providers ────────────
-- system names a built-in client IAMKit registers itself ('org_admin': the hosted
-- organization administration portal); operators never edit it.
CREATE TABLE oauth_clients (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    application_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    redirect_uris text[] NOT NULL,
    public boolean NOT NULL,
    secret_hash bytea DEFAULT '\x'::bytea NOT NULL,
    active boolean DEFAULT true NOT NULL,
    hosted_login boolean DEFAULT false NOT NULL,
    post_logout_redirect_uris text[] DEFAULT '{}'::text[] NOT NULL,
    token_endpoint_auth_method text DEFAULT 'client_secret_basic'::text NOT NULL,
    token_endpoint_auth_signing_alg text DEFAULT 'RS256'::text NOT NULL,
    jwks jsonb,
    jwks_uri text DEFAULT ''::text NOT NULL,
    access_token_format text DEFAULT 'jwt'::text NOT NULL,
    backchannel_logout_uri text DEFAULT ''::text NOT NULL,
    backchannel_logout_session_required boolean DEFAULT false NOT NULL,
    grant_types text[] DEFAULT '{authorization_code,refresh_token}'::text[] NOT NULL,
    system text,
    allowed_origins text[] DEFAULT '{}'::text[] NOT NULL,
    CONSTRAINT oauth_clients_access_token_format_check CHECK ((access_token_format = ANY (ARRAY['jwt'::text, 'opaque'::text]))),
    CONSTRAINT oauth_clients_system_check CHECK ((system = 'org_admin'::text)),
    CONSTRAINT oauth_clients_token_endpoint_auth_method_check CHECK ((token_endpoint_auth_method = ANY (ARRAY['none'::text, 'client_secret_basic'::text, 'client_secret_post'::text, 'private_key_jwt'::text]))),
    CONSTRAINT oauth_clients_token_endpoint_auth_signing_alg_check CHECK ((token_endpoint_auth_signing_alg = ANY (ARRAY['RS256'::text, 'RS384'::text, 'RS512'::text, 'PS256'::text, 'PS384'::text, 'PS512'::text, 'ES256'::text, 'ES384'::text, 'ES512'::text]))),
    CONSTRAINT oauth_clients_pkey PRIMARY KEY (id),
    CONSTRAINT oauth_clients_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT oauth_clients_environment_id_application_id_resource_id_fkey FOREIGN KEY (environment_id, application_id, resource_id) REFERENCES application_resources(environment_id, application_id, resource_id)
);
CREATE INDEX oauth_clients_allowed_origins ON oauth_clients USING gin (allowed_origins) WHERE active;
CREATE UNIQUE INDEX oauth_clients_system ON oauth_clients USING btree (environment_id, system) WHERE (system IS NOT NULL);
CREATE TRIGGER record_changes AFTER UPDATE ON oauth_clients
  FOR EACH ROW
  EXECUTE FUNCTION record_changes();

-- RFC 8628 device authorization: hashed device and user codes.
CREATE TABLE oauth_device_codes (
    device_hash bytea NOT NULL,
    user_hash bytea NOT NULL,
    environment_id uuid NOT NULL,
    client_id uuid NOT NULL,
    scope text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    interval_seconds integer NOT NULL,
    last_poll_at timestamp with time zone,
    session_id uuid,
    user_id uuid,
    organization_id uuid,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_device_codes_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'denied'::text, 'consumed'::text]))),
    CONSTRAINT oauth_device_codes_pkey PRIMARY KEY (device_hash),
    CONSTRAINT oauth_device_codes_user_hash_key UNIQUE (user_hash),
    CONSTRAINT oauth_device_codes_client_id_environment_id_fkey FOREIGN KEY (client_id, environment_id) REFERENCES oauth_clients(id, environment_id)
);
CREATE INDEX oauth_device_codes_expiry ON oauth_device_codes USING btree (expires_at);

CREATE TABLE oauth_authorizations (
    secret_hash bytea NOT NULL,
    environment_id uuid NOT NULL,
    client_id uuid NOT NULL,
    binding_hash bytea NOT NULL,
    request_form text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    device_hash bytea,
    CONSTRAINT oauth_authorizations_pkey PRIMARY KEY (secret_hash),
    CONSTRAINT oauth_authorizations_client_id_environment_id_fkey FOREIGN KEY (client_id, environment_id) REFERENCES oauth_clients(id, environment_id),
    CONSTRAINT oauth_authorizations_device_hash_fkey FOREIGN KEY (device_hash) REFERENCES oauth_device_codes(device_hash) ON DELETE CASCADE
);

CREATE TABLE oauth_requests (
    environment_id uuid NOT NULL,
    kind text NOT NULL,
    signature_hash text NOT NULL,
    client_id uuid NOT NULL,
    request_id text NOT NULL,
    data jsonb NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    active boolean DEFAULT true NOT NULL,
    CONSTRAINT oauth_requests_pkey PRIMARY KEY (environment_id, kind, signature_hash),
    CONSTRAINT oauth_requests_client_id_environment_id_fkey FOREIGN KEY (client_id, environment_id) REFERENCES oauth_clients(id, environment_id)
);
CREATE INDEX oauth_request_family ON oauth_requests USING btree (environment_id, request_id);
CREATE INDEX oauth_requests_signature ON oauth_requests USING btree (kind, signature_hash);

-- private_key_jwt assertions already used (jti replay protection), kept until the
-- assertion expires. hash = SHA-256 of the client-scoped jti.
CREATE TABLE client_assertion_jtis (
    hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT client_assertion_jtis_pkey PRIMARY KEY (hash)
);
CREATE INDEX client_assertion_jtis_expires ON client_assertion_jtis USING btree (expires_at);

CREATE TABLE client_login_settings (
    client_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    display_name text DEFAULT ''::text NOT NULL,
    logo_url text DEFAULT ''::text NOT NULL,
    accent_color text DEFAULT ''::text NOT NULL,
    theme jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    locale text DEFAULT ''::text NOT NULL,
    legal jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT client_login_settings_accent_color_check CHECK (((accent_color = ''::text) OR (accent_color ~ '^#[0-9a-f]{6}$'::text))),
    CONSTRAINT client_login_settings_legal_check CHECK (((jsonb_typeof(legal) = 'object'::text) AND (length((legal)::text) <= 8192))),
    CONSTRAINT client_login_settings_locale_check CHECK ((length(locale) <= 16)),
    CONSTRAINT client_login_settings_pkey PRIMARY KEY (client_id),
    CONSTRAINT client_login_settings_client_id_environment_id_fkey FOREIGN KEY (client_id, environment_id) REFERENCES oauth_clients(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX client_login_settings_environment ON client_login_settings USING btree (environment_id);

-- Which sign-in methods a hosted client offers. No row: all of them.
CREATE TABLE client_sign_in (
    client_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    password boolean NOT NULL,
    email_code boolean NOT NULL,
    organization_sso boolean NOT NULL,
    all_connections boolean NOT NULL,
    connections uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    signup boolean DEFAULT true NOT NULL,
    passkey boolean DEFAULT false NOT NULL,
    CONSTRAINT client_sign_in_pkey PRIMARY KEY (client_id),
    CONSTRAINT client_sign_in_client_id_environment_id_fkey FOREIGN KEY (client_id, environment_id) REFERENCES oauth_clients(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX client_sign_in_environment ON client_sign_in USING btree (environment_id);

-- Custom sign-in texts per environment, client or organization and locale.
CREATE TABLE hosted_texts (
    environment_id uuid NOT NULL,
    client_id uuid,
    organization_id uuid,
    locale text NOT NULL,
    texts jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT hosted_texts_check CHECK (((client_id IS NULL) OR (organization_id IS NULL))),
    CONSTRAINT hosted_texts_locale_check CHECK ((locale ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$'::text)),
    CONSTRAINT hosted_texts_texts_check CHECK (((jsonb_typeof(texts) = 'object'::text) AND (length((texts)::text) <= 262144))),
    CONSTRAINT hosted_texts_client_id_environment_id_fkey FOREIGN KEY (client_id, environment_id) REFERENCES oauth_clients(id, environment_id) ON DELETE CASCADE,
    CONSTRAINT hosted_texts_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE,
    CONSTRAINT hosted_texts_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX hosted_texts_scope ON hosted_texts USING btree (environment_id, COALESCE(client_id, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), locale);

CREATE TABLE saml_service_providers (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    application_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    name text NOT NULL,
    entity_id text NOT NULL,
    acs_urls text[] NOT NULL,
    name_id_format text DEFAULT 'email'::text NOT NULL,
    attributes jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT saml_service_providers_acs_urls_check CHECK ((cardinality(acs_urls) > 0)),
    CONSTRAINT saml_service_providers_name_id_format_check CHECK ((name_id_format = ANY (ARRAY['email'::text, 'persistent'::text]))),
    CONSTRAINT saml_service_providers_pkey PRIMARY KEY (id),
    CONSTRAINT saml_service_providers_environment_id_entity_id_key UNIQUE (environment_id, entity_id),
    CONSTRAINT saml_service_providers_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT saml_service_providers_environment_id_application_id_resou_fkey FOREIGN KEY (environment_id, application_id, resource_id) REFERENCES application_resources(environment_id, application_id, resource_id)
);

CREATE TABLE saml_sso_requests (
    ticket_hash bytea NOT NULL,
    binding_hash bytea NOT NULL,
    environment_id uuid NOT NULL,
    service_provider_id uuid NOT NULL,
    request_id text NOT NULL,
    acs_url text NOT NULL,
    relay_state text DEFAULT ''::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    CONSTRAINT saml_sso_requests_pkey PRIMARY KEY (ticket_hash),
    CONSTRAINT saml_sso_requests_service_provider_id_environment_id_fkey FOREIGN KEY (service_provider_id, environment_id) REFERENCES saml_service_providers(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX saml_sso_requests_expires ON saml_sso_requests USING btree (expires_at);

-- ─── Federation: external identity providers ───────────────────────────
-- A connection belongs to one organization or, with organization_id NULL, serves
-- the whole environment. Organization connections may provision users just in
-- time and can be enforced (one active enforced connection per organization).
-- Environment connections may sign up unknown verified emails (signup_*) and
-- link by email. provider selects the protocol; options holds preset settings
-- and never secrets. The secret is a reference to an approved deployment
-- variable (secret_env) or sealed with IAMKIT_ENCRYPTION_KEY (secret_sealed).
-- saml connections have none; ldap uses the sealed bind password, if any.
CREATE TABLE federation_connections (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    name text NOT NULL,
    issuer text NOT NULL,
    client_id text NOT NULL,
    secret_env text,
    active boolean DEFAULT true NOT NULL,
    organization_id uuid,
    secret_sealed text,
    jit_provisioning boolean DEFAULT false NOT NULL,
    jit_group_id uuid,
    enforcement text DEFAULT 'optional'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    provider text DEFAULT 'oidc'::text NOT NULL,
    options jsonb DEFAULT '{}'::jsonb NOT NULL,
    signup boolean DEFAULT false NOT NULL,
    link_email boolean DEFAULT false NOT NULL,
    signup_organization_id uuid,
    signup_group_id uuid,
    update_profile boolean DEFAULT false NOT NULL,
    CONSTRAINT federation_connections_enforcement_check CHECK ((enforcement = ANY (ARRAY['optional'::text, 'enforced'::text]))),
    CONSTRAINT federation_connections_org_features CHECK (((organization_id IS NOT NULL) OR ((NOT jit_provisioning) AND (jit_group_id IS NULL) AND (enforcement = 'optional'::text)))),
    CONSTRAINT federation_connections_provider_check CHECK ((provider = ANY (ARRAY['oidc'::text, 'google'::text, 'microsoft'::text, 'github'::text, 'apple'::text, 'gitlab'::text, 'github_enterprise'::text, 'oauth2'::text, 'saml'::text, 'ldap'::text]))),
    CONSTRAINT federation_connections_saml CHECK (((provider <> ALL (ARRAY['saml'::text, 'ldap'::text])) OR (organization_id IS NOT NULL))),
    CONSTRAINT federation_connections_secret CHECK (
CASE
    WHEN (provider = 'saml'::text) THEN ((secret_env IS NULL) AND (secret_sealed IS NULL))
    WHEN (provider = 'ldap'::text) THEN (secret_env IS NULL)
    ELSE ((secret_env IS NULL) <> (secret_sealed IS NULL))
END),
    CONSTRAINT federation_connections_signup CHECK (((signup = (signup_organization_id IS NOT NULL)) AND ((signup_group_id IS NULL) OR signup))),
    CONSTRAINT federation_connections_social CHECK (((organization_id IS NULL) OR ((NOT signup) AND (signup_organization_id IS NULL)))),
    CONSTRAINT federation_connections_pkey PRIMARY KEY (id),
    CONSTRAINT federation_connections_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT federation_connections_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id),
    CONSTRAINT federation_connections_jit_group FOREIGN KEY (jit_group_id, environment_id, organization_id) REFERENCES groups(id, environment_id, organization_id) ON DELETE SET NULL (jit_group_id),
    CONSTRAINT federation_connections_organization FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id),
    CONSTRAINT federation_connections_signup_group FOREIGN KEY (signup_group_id, environment_id, signup_organization_id) REFERENCES groups(id, environment_id, organization_id) ON DELETE SET NULL (signup_group_id),
    CONSTRAINT federation_connections_signup_organization FOREIGN KEY (signup_organization_id, environment_id) REFERENCES organizations(id, environment_id)
);
CREATE UNIQUE INDEX federation_connections_client ON federation_connections USING btree (environment_id, COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), issuer, client_id);
CREATE UNIQUE INDEX federation_connections_enforced ON federation_connections USING btree (organization_id) WHERE ((enforcement = 'enforced'::text) AND active);
CREATE INDEX federation_connections_org ON federation_connections USING btree (environment_id, organization_id) WHERE (organization_id IS NOT NULL);

-- How an identity was linked: by an operator, organization JIT, matching verified
-- email, or social sign-up.
CREATE TABLE external_identities (
    connection_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    subject text NOT NULL,
    user_id uuid NOT NULL,
    origin text DEFAULT 'linked'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT external_identities_origin_check CHECK ((origin = ANY (ARRAY['linked'::text, 'jit'::text, 'email'::text, 'signup'::text]))),
    CONSTRAINT external_identities_pkey PRIMARY KEY (connection_id, subject),
    CONSTRAINT external_identities_connection_id_user_id_key UNIQUE (connection_id, user_id),
    CONSTRAINT external_identities_connection_id_environment_id_fkey FOREIGN KEY (connection_id, environment_id) REFERENCES federation_connections(id, environment_id),
    CONSTRAINT external_identities_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id)
);
CREATE TRIGGER external_identities_human BEFORE INSERT ON external_identities
  FOR EACH ROW
  EXECUTE FUNCTION refuse_machine_user();

-- A consumed state drops its continuation: an environment connection state (no
-- organization) must still be consumable.
CREATE TABLE federation_states (
    secret_hash bytea NOT NULL,
    connection_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid,
    application_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    binding_hash bytea NOT NULL,
    nonce text NOT NULL,
    verifier text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    continuation text,
    return_to text,
    return_challenge text,
    CONSTRAINT federation_states_check CHECK (((organization_id IS NOT NULL) OR (continuation IS NOT NULL) OR (consumed_at IS NOT NULL))),
    CONSTRAINT federation_states_check1 CHECK (((return_to IS NULL) = (return_challenge IS NULL))),
    CONSTRAINT federation_states_pkey PRIMARY KEY (secret_hash),
    CONSTRAINT federation_states_connection_id_environment_id_fkey FOREIGN KEY (connection_id, environment_id) REFERENCES federation_connections(id, environment_id),
    CONSTRAINT federation_states_environment_id_application_id_resource_i_fkey FOREIGN KEY (environment_id, application_id, resource_id) REFERENCES application_resources(environment_id, application_id, resource_id),
    CONSTRAINT federation_states_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id)
);

-- A headless login that finished at the provider, parked until the client redeems
-- it with its PKCE verifier. No token is stored.
CREATE TABLE federation_results (
    handle_hash bytea NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    application_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    user_id uuid NOT NULL,
    email text NOT NULL,
    organization_sso boolean NOT NULL,
    no_access boolean NOT NULL,
    challenge text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT federation_results_pkey PRIMARY KEY (handle_hash),
    CONSTRAINT federation_results_environment_id_application_id_resource__fkey FOREIGN KEY (environment_id, application_id, resource_id) REFERENCES application_resources(environment_id, application_id, resource_id) ON DELETE CASCADE,
    CONSTRAINT federation_results_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE,
    CONSTRAINT federation_results_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX federation_results_expires ON federation_results USING btree (expires_at);

-- A SAML response posted to the assertion consumer service waits here for the
-- callback of the browser that started the login. It lives as long as its state.
CREATE TABLE saml_responses (
    handle_hash bytea NOT NULL,
    state_hash bytea NOT NULL,
    response text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT saml_responses_pkey PRIMARY KEY (handle_hash),
    CONSTRAINT saml_responses_state_hash_fkey FOREIGN KEY (state_hash) REFERENCES federation_states(secret_hash) ON DELETE CASCADE
);
CREATE INDEX saml_responses_state ON saml_responses USING btree (state_hash);

-- Assertion IDs a connection accepted, until they expire: a replay is refused.
CREATE TABLE saml_assertions (
    connection_id uuid NOT NULL,
    assertion_id text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT saml_assertions_pkey PRIMARY KEY (connection_id, assertion_id),
    CONSTRAINT saml_assertions_connection_id_fkey FOREIGN KEY (connection_id) REFERENCES federation_connections(id)
);
CREATE INDEX saml_assertions_expires ON saml_assertions USING btree (expires_at);

-- ─── Credentials, sessions and pending logins ──────────────────────────
-- Several second factors per user: TOTP, email and SMS stay one per user, WebAuthn
-- credentials may be many. Only TOTP keeps a sealed secret.
CREATE TABLE user_factors (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    user_id uuid NOT NULL,
    kind text NOT NULL,
    secret_sealed text,
    confirmed_at timestamp with time zone,
    last_step bigint DEFAULT 0 NOT NULL,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    data jsonb DEFAULT '{}'::jsonb NOT NULL,
    code_hash bytea,
    code_expires_at timestamp with time zone,
    code_sent_at timestamp with time zone,
    code_attempts integer DEFAULT 0 NOT NULL,
    codes_sent integer DEFAULT 0 NOT NULL,
    codes_window timestamp with time zone,
    credential_id bytea,
    passkey boolean DEFAULT false NOT NULL,
    CONSTRAINT user_factors_credential CHECK (((kind <> 'webauthn'::text) OR (credential_id IS NOT NULL))),
    CONSTRAINT user_factors_kind_check CHECK ((kind = ANY (ARRAY['totp'::text, 'email'::text, 'sms'::text, 'webauthn'::text]))),
    CONSTRAINT user_factors_secret CHECK (((kind <> 'totp'::text) OR (secret_sealed IS NOT NULL))),
    CONSTRAINT user_factors_pkey PRIMARY KEY (id),
    CONSTRAINT user_factors_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX user_factors_credential_id ON user_factors USING btree (environment_id, credential_id) WHERE (credential_id IS NOT NULL);
CREATE UNIQUE INDEX user_factors_single ON user_factors USING btree (environment_id, user_id, kind) WHERE (kind = ANY (ARRAY['totp'::text, 'email'::text, 'sms'::text]));
CREATE TRIGGER user_factors_human BEFORE INSERT ON user_factors
  FOR EACH ROW
  EXECUTE FUNCTION refuse_machine_user();

-- Wrong second-factor codes count per user, not per factor, so switching factor
-- does not reset the count.
CREATE TABLE user_mfa_state (
    environment_id uuid NOT NULL,
    user_id uuid NOT NULL,
    failed_attempts integer DEFAULT 0 NOT NULL,
    locked_until timestamp with time zone,
    CONSTRAINT user_mfa_state_pkey PRIMARY KEY (environment_id, user_id),
    CONSTRAINT user_mfa_state_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);

CREATE TABLE recovery_codes (
    environment_id uuid NOT NULL,
    user_id uuid NOT NULL,
    code_hash bytea NOT NULL,
    used_at timestamp with time zone,
    CONSTRAINT recovery_codes_pkey PRIMARY KEY (environment_id, user_id, code_hash),
    CONSTRAINT recovery_codes_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);

CREATE TABLE webauthn_sessions (
    id_hash bytea NOT NULL,
    environment_id uuid NOT NULL,
    user_id uuid,
    purpose text NOT NULL,
    data jsonb NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT webauthn_sessions_purpose_check CHECK ((purpose = ANY (ARRAY['register'::text, 'login'::text, 'passkey'::text]))),
    CONSTRAINT webauthn_sessions_pkey PRIMARY KEY (id_hash),
    CONSTRAINT webauthn_sessions_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE,
    CONSTRAINT webauthn_sessions_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX webauthn_sessions_expires ON webauthn_sessions USING btree (expires_at);

-- Personal access tokens (ik_pat_, only the SHA-256 is stored): act as a machine
-- user in one organization for one application resource.
CREATE TABLE user_access_tokens (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    user_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    application_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    name text NOT NULL,
    secret_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_access_tokens_name_check CHECK ((length(TRIM(BOTH FROM name)) > 0)),
    CONSTRAINT user_access_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT user_access_tokens_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT user_access_tokens_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT user_access_tokens_environment_id_application_id_resource__fkey FOREIGN KEY (environment_id, application_id, resource_id) REFERENCES application_resources(environment_id, application_id, resource_id),
    CONSTRAINT user_access_tokens_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE,
    CONSTRAINT user_access_tokens_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX user_access_tokens_user ON user_access_tokens USING btree (environment_id, user_id, created_at DESC);

-- Public keys of machine users for the RFC 7523 jwt-bearer grant.
CREATE TABLE user_keys (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    user_id uuid NOT NULL,
    public_jwk jsonb NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_keys_pkey PRIMARY KEY (id),
    CONSTRAINT user_keys_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT user_keys_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX user_keys_user ON user_keys USING btree (environment_id, user_id, created_at DESC);

CREATE TABLE service_accounts (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    application_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    name text NOT NULL,
    permissions text[] DEFAULT '{}'::text[] NOT NULL,
    secret_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    token_endpoint_auth_method text DEFAULT 'client_secret_basic'::text NOT NULL,
    token_endpoint_auth_signing_alg text DEFAULT 'RS256'::text NOT NULL,
    jwks jsonb,
    jwks_uri text DEFAULT ''::text NOT NULL,
    can_impersonate boolean DEFAULT false NOT NULL,
    CONSTRAINT service_accounts_token_endpoint_auth_method_check CHECK ((token_endpoint_auth_method = ANY (ARRAY['client_secret_basic'::text, 'client_secret_post'::text, 'private_key_jwt'::text]))),
    CONSTRAINT service_accounts_token_endpoint_auth_signing_alg_check CHECK ((token_endpoint_auth_signing_alg = ANY (ARRAY['RS256'::text, 'RS384'::text, 'RS512'::text, 'PS256'::text, 'PS384'::text, 'PS512'::text, 'ES256'::text, 'ES384'::text, 'ES512'::text]))),
    CONSTRAINT service_accounts_pkey PRIMARY KEY (id),
    CONSTRAINT service_accounts_secret_hash_key UNIQUE (secret_hash),
    CONSTRAINT service_accounts_environment_id_application_id_resource_id_fkey FOREIGN KEY (environment_id, application_id, resource_id) REFERENCES application_resources(environment_id, application_id, resource_id)
);
CREATE TRIGGER service_catalog BEFORE INSERT OR UPDATE ON service_accounts
  FOR EACH ROW
  EXECUTE FUNCTION enforce_permission_catalog();

-- parent_session_id: a token-exchange child session, one live child per parent and
-- resource, ended with its parent (trigger). actor_id (operator) and
-- actor_account_id (service account) mark impersonation, which needs a reason.
CREATE TABLE sessions (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    user_id uuid NOT NULL,
    application_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    actor_id uuid,
    impersonation_reason text,
    authenticated_at timestamp with time zone DEFAULT now() NOT NULL,
    amr text[] DEFAULT '{}'::text[] NOT NULL,
    oauth_client_id uuid,
    parent_session_id uuid,
    actor_account_id uuid,
    access_token_id uuid,
    user_key_id uuid,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT impersonation_attribution CHECK ((((actor_id IS NULL) AND (actor_account_id IS NULL) AND (impersonation_reason IS NULL)) OR ((num_nonnulls(actor_id, actor_account_id) = 1) AND (length(TRIM(BOTH FROM impersonation_reason)) >= 10)))),
    CONSTRAINT sessions_pkey PRIMARY KEY (id),
    CONSTRAINT sessions_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT sessions_access_token_id_fkey FOREIGN KEY (access_token_id) REFERENCES user_access_tokens(id) ON DELETE CASCADE,
    CONSTRAINT sessions_actor_account_id_fkey FOREIGN KEY (actor_account_id) REFERENCES service_accounts(id) ON DELETE CASCADE,
    CONSTRAINT sessions_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES operators(id),
    CONSTRAINT sessions_environment_id_application_id_resource_id_fkey FOREIGN KEY (environment_id, application_id, resource_id) REFERENCES application_resources(environment_id, application_id, resource_id),
    CONSTRAINT sessions_environment_id_organization_id_user_id_fkey FOREIGN KEY (environment_id, organization_id, user_id) REFERENCES memberships(environment_id, organization_id, user_id),
    CONSTRAINT sessions_parent_session_id_fkey FOREIGN KEY (parent_session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    CONSTRAINT sessions_user_key_id_fkey FOREIGN KEY (user_key_id) REFERENCES user_keys(id) ON DELETE SET NULL
);

-- Queue a back-channel logout when a client session ends.
CREATE FUNCTION queue_logout_notification() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  s sessions%ROWTYPE;
BEGIN
  IF TG_OP = 'DELETE' THEN
    s := OLD;
  ELSE
    s := NEW;
  END IF;
  IF s.oauth_client_id IS NULL OR OLD.revoked_at IS NOT NULL OR s.expires_at <= now() THEN
    RETURN NULL;
  END IF;
  INSERT INTO logout_notifications (environment_id, client_id, session_id, subject)
    SELECT s.environment_id, c.id, s.id, s.user_id FROM oauth_clients c
    WHERE c.id = s.oauth_client_id AND c.environment_id = s.environment_id
      AND c.active AND c.backchannel_logout_uri <> '';
  RETURN NULL;
END $$;

-- session.created / session.revoked events for every way a session starts or ends.
CREATE FUNCTION session_event() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  s sessions%ROWTYPE;
  kind text := 'user';
  actor text;
  t text;
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
  IF s.actor_id IS NOT NULL THEN
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
      'expires_at', CASE WHEN t = 'session.created' THEN s.expires_at END))
  WHERE EXISTS (SELECT 1 FROM environments WHERE id = s.environment_id);
  RETURN NULL;
END $$;

CREATE INDEX sessions_access_token ON sessions USING btree (access_token_id) WHERE (access_token_id IS NOT NULL);
CREATE UNIQUE INDEX sessions_exchange_child ON sessions USING btree (parent_session_id, resource_id) WHERE ((parent_session_id IS NOT NULL) AND (revoked_at IS NULL));
CREATE INDEX sessions_newest ON sessions USING btree (environment_id, created_at DESC, id DESC);
CREATE INDEX sessions_user_key ON sessions USING btree (user_key_id) WHERE (user_key_id IS NOT NULL);
CREATE INDEX sessions_user_newest ON sessions USING btree (environment_id, user_id, created_at DESC, id DESC);
CREATE TRIGGER session_children_ended AFTER UPDATE OF revoked_at ON sessions
  FOR EACH ROW WHEN (((old.revoked_at IS NULL) AND (new.revoked_at IS NOT NULL)))
  EXECUTE FUNCTION end_child_sessions();
CREATE TRIGGER session_created_event AFTER INSERT ON sessions
  FOR EACH ROW
  EXECUTE FUNCTION session_event();
CREATE TRIGGER session_deleted AFTER DELETE ON sessions
  FOR EACH ROW
  EXECUTE FUNCTION queue_logout_notification();
CREATE TRIGGER session_deleted_event AFTER DELETE ON sessions
  FOR EACH ROW
  EXECUTE FUNCTION session_event();
CREATE TRIGGER session_ended AFTER UPDATE OF revoked_at ON sessions
  FOR EACH ROW WHEN (((old.revoked_at IS NULL) AND (new.revoked_at IS NOT NULL)))
  EXECUTE FUNCTION queue_logout_notification();
CREATE TRIGGER session_revoked_event AFTER UPDATE OF revoked_at ON sessions
  FOR EACH ROW WHEN (((old.revoked_at IS NULL) AND (new.revoked_at IS NOT NULL)))
  EXECUTE FUNCTION session_event();

CREATE TABLE refresh_tokens (
    secret_hash bytea NOT NULL,
    session_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    CONSTRAINT refresh_tokens_pkey PRIMARY KEY (secret_hash),
    CONSTRAINT refresh_tokens_session_id_environment_id_fkey FOREIGN KEY (session_id, environment_id) REFERENCES sessions(id, environment_id)
);

CREATE TABLE identity_challenges (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    user_id uuid NOT NULL,
    purpose text NOT NULL,
    secret_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    attempts integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT identity_challenges_purpose_check CHECK ((purpose = ANY (ARRAY['login'::text, 'password_reset'::text, 'email_verification'::text]))),
    CONSTRAINT identity_challenges_pkey PRIMARY KEY (id),
    CONSTRAINT identity_challenges_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id)
);
CREATE INDEX challenge_user ON identity_challenges USING btree (environment_id, user_id, purpose, created_at);
CREATE TRIGGER identity_challenges_human BEFORE INSERT ON identity_challenges
  FOR EACH ROW
  EXECUTE FUNCTION refuse_machine_user();

CREATE TABLE mfa_logins (
    token_hash bytea NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    application_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    user_id uuid NOT NULL,
    amr text[] NOT NULL,
    enroll boolean DEFAULT false NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    password_hash text DEFAULT ''::text NOT NULL,
    CONSTRAINT mfa_logins_pkey PRIMARY KEY (token_hash),
    CONSTRAINT mfa_logins_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id),
    CONSTRAINT mfa_logins_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX mfa_logins_expires ON mfa_logins USING btree (expires_at);
CREATE INDEX mfa_logins_user ON mfa_logins USING btree (user_id, environment_id);

CREATE TABLE hosted_logins (
    ticket_hash bytea NOT NULL,
    environment_id uuid NOT NULL,
    user_id uuid NOT NULL,
    email text NOT NULL,
    method text NOT NULL,
    organization_id uuid,
    expires_at timestamp with time zone NOT NULL,
    amr text[] DEFAULT '{}'::text[] NOT NULL,
    chosen_organization_id uuid,
    mfa_attempts integer DEFAULT 0 NOT NULL,
    password_change boolean DEFAULT false NOT NULL,
    CONSTRAINT hosted_logins_method_check CHECK ((method = ANY (ARRAY['password'::text, 'code'::text, 'sso'::text, 'passkey'::text]))),
    CONSTRAINT hosted_logins_pkey PRIMARY KEY (ticket_hash),
    CONSTRAINT hosted_logins_chosen_organization_id_environment_id_fkey FOREIGN KEY (chosen_organization_id, environment_id) REFERENCES organizations(id, environment_id),
    CONSTRAINT hosted_logins_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id),
    CONSTRAINT hosted_logins_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);

-- Self-registrations waiting for their email code. No user exists until the code
-- is verified. password_hash is '' for a passwordless account.
CREATE TABLE signups (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    email text NOT NULL,
    name text NOT NULL,
    password_hash text NOT NULL,
    secret_hash bytea NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    terms_accepted_at timestamp with time zone,
    CONSTRAINT signups_name_check CHECK ((length(TRIM(BOTH FROM name)) > 0)),
    CONSTRAINT signups_pkey PRIMARY KEY (id),
    CONSTRAINT signups_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id)
);
CREATE INDEX signups_email ON signups USING btree (environment_id, email, created_at);

CREATE TABLE phone_verifications (
    user_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    phone text NOT NULL,
    code_hash bytea,
    expires_at timestamp with time zone,
    sent_at timestamp with time zone NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    codes_sent integer DEFAULT 0 NOT NULL,
    codes_window timestamp with time zone NOT NULL,
    CONSTRAINT phone_verifications_phone_check CHECK ((phone ~ '^\+[1-9][0-9]{6,14}$'::text)),
    CONSTRAINT phone_verifications_pkey PRIMARY KEY (user_id),
    CONSTRAINT phone_verifications_user_id_environment_id_fkey FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
CREATE TRIGGER phone_verifications_human BEFORE INSERT ON phone_verifications
  FOR EACH ROW
  EXECUTE FUNCTION refuse_machine_user();

CREATE TABLE invitations (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    organization_id uuid NOT NULL,
    email text NOT NULL,
    role_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    group_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    inviter text NOT NULL,
    token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    accepted_at timestamp with time zone,
    accepted_user_id uuid,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT invitations_check CHECK (((accepted_at IS NULL) = (accepted_user_id IS NULL))),
    CONSTRAINT invitations_check1 CHECK (((accepted_at IS NULL) OR (revoked_at IS NULL))),
    CONSTRAINT invitations_email_check CHECK ((email = lower(TRIM(BOTH FROM email)))),
    CONSTRAINT invitations_pkey PRIMARY KEY (id),
    CONSTRAINT invitations_token_hash_key UNIQUE (token_hash),
    CONSTRAINT invitations_organization_id_environment_id_fkey FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id)
);
CREATE INDEX invitations_email ON invitations USING btree (environment_id, email);
CREATE INDEX invitations_org ON invitations USING btree (environment_id, organization_id, created_at DESC);
CREATE UNIQUE INDEX invitations_pending ON invitations USING btree (organization_id, email) WHERE ((accepted_at IS NULL) AND (revoked_at IS NULL));

-- Back-channel logout outbox, filled by trigger when a client session ends.
CREATE TABLE logout_notifications (
    id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
    environment_id uuid NOT NULL,
    client_id uuid NOT NULL,
    session_id uuid NOT NULL,
    subject uuid NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    delivered_at timestamp with time zone,
    failed_at timestamp with time zone,
    last_error text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT logout_notifications_pkey PRIMARY KEY (id)
);
CREATE INDEX logout_notifications_due ON logout_notifications USING btree (next_attempt_at) WHERE ((delivered_at IS NULL) AND (failed_at IS NULL));

-- ─── Per-environment settings ──────────────────────────────────────────
CREATE TABLE sign_in_policies (
    environment_id uuid NOT NULL,
    allow_password boolean NOT NULL,
    allow_email_code boolean NOT NULL,
    allow_social boolean NOT NULL,
    allow_password_reset boolean NOT NULL,
    mfa_required boolean NOT NULL,
    mfa_for_federated boolean NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    allow_signup boolean DEFAULT false NOT NULL,
    signup_organization_id uuid,
    signup_group_id uuid,
    allowed_factors text[] DEFAULT '{totp,webauthn}'::text[] NOT NULL,
    allow_passkey boolean DEFAULT true NOT NULL,
    require_terms boolean DEFAULT false NOT NULL,
    CONSTRAINT sign_in_policies_allowed_factors_check CHECK ((allowed_factors <@ ARRAY['totp'::text, 'email'::text, 'sms'::text, 'webauthn'::text])),
    CONSTRAINT sign_in_policies_signup CHECK ((((NOT allow_signup) OR (signup_organization_id IS NOT NULL)) AND ((signup_group_id IS NULL) OR (signup_organization_id IS NOT NULL)))),
    CONSTRAINT sign_in_policies_pkey PRIMARY KEY (environment_id),
    CONSTRAINT sign_in_policies_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id),
    CONSTRAINT sign_in_policies_signup_group FOREIGN KEY (signup_group_id, environment_id, signup_organization_id) REFERENCES groups(id, environment_id, organization_id) ON DELETE SET NULL (signup_group_id),
    CONSTRAINT sign_in_policies_signup_organization FOREIGN KEY (signup_organization_id, environment_id) REFERENCES organizations(id, environment_id)
);

CREATE TABLE password_policies (
    environment_id uuid NOT NULL,
    min_length integer NOT NULL,
    require_upper boolean NOT NULL,
    require_lower boolean NOT NULL,
    require_digit boolean NOT NULL,
    require_symbol boolean NOT NULL,
    max_age_days integer NOT NULL,
    lockout_threshold integer NOT NULL,
    lockout_minutes integer NOT NULL,
    breach_check boolean NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT password_policies_lockout_minutes_check CHECK (((lockout_minutes >= 1) AND (lockout_minutes <= 1440))),
    CONSTRAINT password_policies_lockout_threshold_check CHECK (((lockout_threshold >= 0) AND (lockout_threshold <= 100))),
    CONSTRAINT password_policies_max_age_days_check CHECK (((max_age_days >= 0) AND (max_age_days <= 3650))),
    CONSTRAINT password_policies_min_length_check CHECK (((min_length >= 8) AND (min_length <= 72))),
    CONSTRAINT password_policies_pkey PRIMARY KEY (environment_id),
    CONSTRAINT password_policies_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id)
);

CREATE TABLE login_settings (
    environment_id uuid NOT NULL,
    display_name text DEFAULT ''::text NOT NULL,
    logo_url text DEFAULT ''::text NOT NULL,
    accent_color text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    theme jsonb DEFAULT '{}'::jsonb NOT NULL,
    locale text DEFAULT ''::text NOT NULL,
    languages text[] DEFAULT '{}'::text[] NOT NULL,
    legal jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT login_settings_accent_color_check CHECK (((accent_color = ''::text) OR (accent_color ~ '^#[0-9a-f]{6}$'::text))),
    CONSTRAINT login_settings_languages_check CHECK ((cardinality(languages) <= 64)),
    CONSTRAINT login_settings_legal_check CHECK (((jsonb_typeof(legal) = 'object'::text) AND (length((legal)::text) <= 8192))),
    CONSTRAINT login_settings_locale_check CHECK ((length(locale) <= 16)),
    CONSTRAINT login_settings_pkey PRIMARY KEY (environment_id),
    CONSTRAINT login_settings_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id)
);

-- provider selects how an environment sends email: the customer's webhook, SMTP or
-- Resend. Only the columns of the chosen provider are set. secret_sealed holds
-- the SMTP password, Resend API key or (with an encryption key) the webhook token.
CREATE TABLE delivery_configs (
    environment_id uuid NOT NULL,
    webhook_url text DEFAULT ''::text NOT NULL,
    webhook_token text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    invitation_url text DEFAULT ''::text NOT NULL,
    provider text DEFAULT 'webhook'::text NOT NULL,
    from_email text DEFAULT ''::text NOT NULL,
    from_name text DEFAULT ''::text NOT NULL,
    reply_to text DEFAULT ''::text NOT NULL,
    smtp_host text DEFAULT ''::text NOT NULL,
    smtp_port integer,
    smtp_username text DEFAULT ''::text NOT NULL,
    smtp_tls text DEFAULT ''::text NOT NULL,
    secret_sealed text DEFAULT ''::text NOT NULL,
    CONSTRAINT delivery_configs_from_name_check CHECK ((length(from_name) <= 100)),
    CONSTRAINT delivery_configs_provider_check CHECK ((provider = ANY (ARRAY['webhook'::text, 'smtp'::text, 'resend'::text]))),
    CONSTRAINT delivery_configs_provider_settings CHECK ((((provider = 'webhook'::text) AND (webhook_url <> ''::text) AND ((webhook_token = ''::text) <> (secret_sealed = ''::text)) AND (from_email = ''::text) AND (smtp_host = ''::text) AND (smtp_port IS NULL)) OR ((provider = 'smtp'::text) AND (from_email <> ''::text) AND (smtp_host <> ''::text) AND (smtp_port IS NOT NULL) AND (smtp_tls <> ''::text) AND (webhook_url = ''::text) AND (webhook_token = ''::text)) OR ((provider = 'resend'::text) AND (from_email <> ''::text) AND (secret_sealed <> ''::text) AND (smtp_host = ''::text) AND (smtp_port IS NULL) AND (webhook_url = ''::text) AND (webhook_token = ''::text)))),
    CONSTRAINT delivery_configs_smtp_port_check CHECK (((smtp_port >= 1) AND (smtp_port <= 65535))),
    CONSTRAINT delivery_configs_smtp_tls_check CHECK ((smtp_tls = ANY (ARRAY[''::text, 'starttls'::text, 'tls'::text]))),
    CONSTRAINT delivery_configs_pkey PRIMARY KEY (environment_id),
    CONSTRAINT delivery_configs_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id)
);

-- The outcome of the latest delivery attempt per channel and, kept across later
-- successes, of the latest failure. Only fixed, secret-free descriptions.
CREATE TABLE delivery_activity (
    environment_id uuid NOT NULL,
    source text NOT NULL,
    purpose text NOT NULL,
    delivered boolean NOT NULL,
    status integer,
    reason text DEFAULT ''::text NOT NULL,
    latency_ms integer NOT NULL,
    attempted_at timestamp with time zone NOT NULL,
    failure_source text,
    failure_purpose text,
    failure_status integer,
    failure_reason text,
    failed_at timestamp with time zone,
    channel text DEFAULT 'email'::text NOT NULL,
    CONSTRAINT delivery_activity_channel_check CHECK ((channel = ANY (ARRAY['email'::text, 'sms'::text]))),
    CONSTRAINT delivery_activity_check CHECK ((((failed_at IS NULL) = (failure_purpose IS NULL)) AND ((failed_at IS NULL) = (failure_source IS NULL)))),
    CONSTRAINT delivery_activity_check1 CHECK ((delivered OR (failed_at = attempted_at))),
    CONSTRAINT delivery_activity_failure_purpose_check CHECK ((failure_purpose = ANY (ARRAY['login'::text, 'password_reset'::text, 'email_verification'::text, 'invitation'::text, 'test'::text, 'mfa'::text, 'phone_verification'::text]))),
    CONSTRAINT delivery_activity_failure_reason_check CHECK ((length(failure_reason) <= 200)),
    CONSTRAINT delivery_activity_failure_source_check CHECK ((failure_source = ANY (ARRAY['environment'::text, 'global'::text, 'none'::text]))),
    CONSTRAINT delivery_activity_failure_status_check CHECK (((failure_status >= 100) AND (failure_status <= 599))),
    CONSTRAINT delivery_activity_latency_ms_check CHECK ((latency_ms >= 0)),
    CONSTRAINT delivery_activity_purpose_check CHECK ((purpose = ANY (ARRAY['login'::text, 'password_reset'::text, 'email_verification'::text, 'invitation'::text, 'test'::text, 'mfa'::text, 'phone_verification'::text]))),
    CONSTRAINT delivery_activity_reason_check CHECK ((length(reason) <= 200)),
    CONSTRAINT delivery_activity_source_check CHECK ((source = ANY (ARRAY['environment'::text, 'global'::text, 'none'::text]))),
    CONSTRAINT delivery_activity_status_check CHECK (((status >= 100) AND (status <= 599))),
    CONSTRAINT delivery_activity_pkey PRIMARY KEY (environment_id, channel),
    CONSTRAINT delivery_activity_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id)
);

CREATE TABLE sms_configs (
    environment_id uuid NOT NULL,
    provider text NOT NULL,
    account_sid text DEFAULT ''::text NOT NULL,
    from_number text DEFAULT ''::text NOT NULL,
    messaging_service_sid text DEFAULT ''::text NOT NULL,
    webhook_url text DEFAULT ''::text NOT NULL,
    secret_sealed text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sms_configs_check CHECK ((((provider = 'twilio'::text) AND (account_sid <> ''::text) AND ((from_number <> ''::text) OR (messaging_service_sid <> ''::text)) AND (webhook_url = ''::text)) OR ((provider = 'webhook'::text) AND (webhook_url <> ''::text) AND (account_sid = ''::text) AND (from_number = ''::text) AND (messaging_service_sid = ''::text)))),
    CONSTRAINT sms_configs_provider_check CHECK ((provider = ANY (ARRAY['twilio'::text, 'webhook'::text]))),
    CONSTRAINT sms_configs_pkey PRIMARY KEY (environment_id),
    CONSTRAINT sms_configs_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id)
);

-- Customized wording of the emails IAMKit renders. Only text is stored; the layout
-- stays IAMKit's. No row keeps every default.
CREATE TABLE email_templates (
    environment_id uuid NOT NULL,
    purpose text NOT NULL,
    locale text NOT NULL,
    subject text DEFAULT ''::text NOT NULL,
    heading text DEFAULT ''::text NOT NULL,
    body text DEFAULT ''::text NOT NULL,
    action text DEFAULT ''::text NOT NULL,
    footer text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT email_templates_action_check CHECK ((char_length(action) <= 60)),
    CONSTRAINT email_templates_body_check CHECK ((char_length(body) <= 2000)),
    CONSTRAINT email_templates_check CHECK (((action = ''::text) OR (purpose = 'invitation'::text))),
    CONSTRAINT email_templates_check1 CHECK (((subject <> ''::text) OR (heading <> ''::text) OR (body <> ''::text) OR (action <> ''::text) OR (footer <> ''::text))),
    CONSTRAINT email_templates_footer_check CHECK ((char_length(footer) <= 500)),
    CONSTRAINT email_templates_heading_check CHECK ((char_length(heading) <= 200)),
    CONSTRAINT email_templates_locale_check CHECK (((length(locale) >= 2) AND (length(locale) <= 16))),
    CONSTRAINT email_templates_purpose_check CHECK ((purpose = ANY (ARRAY['login'::text, 'password_reset'::text, 'email_verification'::text, 'invitation'::text, 'test'::text, 'mfa'::text]))),
    CONSTRAINT email_templates_subject_check CHECK ((char_length(subject) <= 200)),
    CONSTRAINT email_templates_pkey PRIMARY KEY (environment_id, purpose, locale),
    CONSTRAINT email_templates_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id)
);

CREATE TABLE signing_keys (
    id text NOT NULL,
    environment_id uuid NOT NULL,
    algorithm text DEFAULT 'RS256'::text NOT NULL,
    private_sealed text NOT NULL,
    public_der bytea NOT NULL,
    state text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    activated_at timestamp with time zone,
    retire_after timestamp with time zone,
    retired_at timestamp with time zone,
    CONSTRAINT signing_keys_algorithm_check CHECK ((algorithm = 'RS256'::text)),
    CONSTRAINT signing_keys_state_check CHECK ((state = ANY (ARRAY['next'::text, 'active'::text, 'retiring'::text, 'retired'::text]))),
    CONSTRAINT signing_keys_pkey PRIMARY KEY (id),
    CONSTRAINT signing_keys_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id)
);
CREATE INDEX signing_keys_environment ON signing_keys USING btree (environment_id, created_at DESC);
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys USING btree (environment_id) WHERE (state = 'active'::text);

CREATE TABLE user_schemas (
    environment_id uuid NOT NULL,
    schema jsonb NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_schemas_schema_check CHECK ((jsonb_typeof(schema) = 'object'::text)),
    CONSTRAINT user_schemas_pkey PRIMARY KEY (environment_id),
    CONSTRAINT user_schemas_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);

-- IAMKit's own feature flags overridden per environment (registry: config.Flags).
CREATE TABLE environment_features (
    environment_id uuid NOT NULL,
    name text NOT NULL,
    enabled boolean NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT environment_features_name_check CHECK ((name ~ '^[a-z][a-z0-9_]{0,63}$'::text)),
    CONSTRAINT environment_features_pkey PRIMARY KEY (environment_id, name),
    CONSTRAINT environment_features_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);

-- NULL means the deployment limit applies.
CREATE TABLE environment_limits (
    environment_id uuid NOT NULL,
    users_max bigint,
    organizations_max bigint,
    applications_max bigint,
    requests_per_minute bigint,
    emails_per_day bigint,
    sms_per_day bigint,
    action_calls_per_minute bigint,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT environment_limits_action_calls_per_minute_check CHECK ((action_calls_per_minute >= 0)),
    CONSTRAINT environment_limits_applications_max_check CHECK ((applications_max >= 0)),
    CONSTRAINT environment_limits_emails_per_day_check CHECK ((emails_per_day >= 0)),
    CONSTRAINT environment_limits_organizations_max_check CHECK ((organizations_max >= 0)),
    CONSTRAINT environment_limits_requests_per_minute_check CHECK ((requests_per_minute >= 0)),
    CONSTRAINT environment_limits_sms_per_day_check CHECK ((sms_per_day >= 0)),
    CONSTRAINT environment_limits_users_max_check CHECK ((users_max >= 0)),
    CONSTRAINT environment_limits_pkey PRIMARY KEY (environment_id),
    CONSTRAINT environment_limits_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);

-- ─── Audit, events, actions and usage ──────────────────────────────────
-- actor_kind and organization_id are filled by trigger, so writers insert four columns.
CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
    environment_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    action text NOT NULL,
    target_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    actor_kind text DEFAULT 'operator'::text NOT NULL,
    organization_id uuid,
    CONSTRAINT audit_events_actor_kind_check CHECK ((actor_kind = ANY (ARRAY['operator'::text, 'user'::text, 'service_account'::text, 'system'::text]))),
    CONSTRAINT audit_events_pkey PRIMARY KEY (id),
    CONSTRAINT audit_events_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id)
);
CREATE INDEX audit_environment ON audit_events USING btree (environment_id, id);
CREATE INDEX audit_events_organization ON audit_events USING btree (environment_id, organization_id, id DESC) WHERE (organization_id IS NOT NULL);
CREATE TRIGGER audit_event_context BEFORE INSERT ON audit_events
  FOR EACH ROW
  EXECUTE FUNCTION audit_event_context();

-- Semantic event log (transactional outbox), append-only, pruned by a worker job.
CREATE TABLE events (
    id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
    environment_id uuid NOT NULL,
    type text NOT NULL,
    actor_kind text NOT NULL,
    actor_id text DEFAULT ''::text NOT NULL,
    subject_kind text DEFAULT ''::text NOT NULL,
    subject_id text DEFAULT ''::text NOT NULL,
    organization_id uuid,
    data jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT events_actor_kind_check CHECK ((actor_kind = ANY (ARRAY['operator'::text, 'user'::text, 'service_account'::text, 'directory'::text, 'system'::text]))),
    CONSTRAINT events_data_check CHECK ((jsonb_typeof(data) = 'object'::text)),
    CONSTRAINT events_type_check CHECK ((type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'::text)),
    CONSTRAINT events_pkey PRIMARY KEY (id),
    CONSTRAINT events_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);
CREATE INDEX events_created ON events USING btree (created_at);
CREATE INDEX events_environment ON events USING btree (environment_id, id);
CREATE INDEX events_subject ON events USING btree (environment_id, subject_id, id) WHERE (subject_id <> ''::text);
CREATE INDEX events_type ON events USING btree (environment_id, type, id);
CREATE TRIGGER event_actor BEFORE INSERT ON events
  FOR EACH ROW
  EXECUTE FUNCTION event_actor();
CREATE TRIGGER event_changes BEFORE INSERT ON events
  FOR EACH ROW
  EXECUTE FUNCTION event_changes();
CREATE TRIGGER queue_event_deliveries AFTER INSERT ON events
  FOR EACH ROW
  EXECUTE FUNCTION queue_event_deliveries();

CREATE TABLE event_subscriptions (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    name text NOT NULL,
    url text NOT NULL,
    types text[] DEFAULT '{}'::text[] NOT NULL,
    secret_sealed text NOT NULL,
    previous_sealed text,
    previous_expires_at timestamp with time zone,
    active boolean DEFAULT true NOT NULL,
    failing_since timestamp with time zone,
    disabled_reason text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT event_subscriptions_name_check CHECK (((length(name) >= 1) AND (length(name) <= 100))),
    CONSTRAINT event_subscriptions_pkey PRIMARY KEY (id),
    CONSTRAINT event_subscriptions_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);
CREATE INDEX event_subscriptions_environment ON event_subscriptions USING btree (environment_id) WHERE active;

-- Webhook outbox. event_id is not a foreign key: pruned events deliver as failed.
CREATE TABLE event_deliveries (
    id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
    subscription_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    event_id bigint NOT NULL,
    event_type text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    response_status integer,
    last_error text DEFAULT ''::text NOT NULL,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    first_attempt_at timestamp with time zone,
    finished_at timestamp with time zone,
    CONSTRAINT event_deliveries_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'delivered'::text, 'failed'::text]))),
    CONSTRAINT event_deliveries_pkey PRIMARY KEY (id),
    CONSTRAINT event_deliveries_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE,
    CONSTRAINT event_deliveries_subscription_id_fkey FOREIGN KEY (subscription_id) REFERENCES event_subscriptions(id) ON DELETE CASCADE
);
CREATE INDEX event_deliveries_finished ON event_deliveries USING btree (finished_at) WHERE (status <> 'pending'::text);
CREATE INDEX event_deliveries_pending ON event_deliveries USING btree (subscription_id, id) WHERE (status = 'pending'::text);
CREATE INDEX event_deliveries_subscription ON event_deliveries USING btree (subscription_id, id);

CREATE TABLE action_targets (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    name text NOT NULL,
    url text NOT NULL,
    kind text NOT NULL,
    timeout_ms integer NOT NULL,
    interrupt_on_error boolean DEFAULT false NOT NULL,
    secret_sealed text NOT NULL,
    previous_sealed text,
    previous_expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT action_targets_kind_check CHECK ((kind = ANY (ARRAY['call'::text, 'webhook'::text, 'async'::text]))),
    CONSTRAINT action_targets_name_check CHECK (((length(name) >= 1) AND (length(name) <= 100))),
    CONSTRAINT action_targets_timeout_ms_check CHECK (((timeout_ms >= 100) AND (timeout_ms <= 10000))),
    CONSTRAINT action_targets_pkey PRIMARY KEY (id),
    CONSTRAINT action_targets_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);
CREATE INDEX action_targets_environment ON action_targets USING btree (environment_id);
CREATE TRIGGER action_target_deleted BEFORE DELETE ON action_targets
  FOR EACH ROW
  EXECUTE FUNCTION action_target_deleted();

-- Ordered targets per condition; a deleted target is removed (trigger).
CREATE TABLE action_executions (
    environment_id uuid NOT NULL,
    condition text NOT NULL,
    target_ids uuid[] NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT action_executions_target_ids_check CHECK (((cardinality(target_ids) >= 1) AND (cardinality(target_ids) <= 5))),
    CONSTRAINT action_executions_pkey PRIMARY KEY (environment_id, condition),
    CONSTRAINT action_executions_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);

CREATE TABLE action_calls (
    id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
    environment_id uuid NOT NULL,
    target_id uuid NOT NULL,
    condition text NOT NULL,
    outcome text NOT NULL,
    status integer,
    duration_ms integer DEFAULT 0 NOT NULL,
    error text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT action_calls_outcome_check CHECK ((outcome = ANY (ARRAY['ok'::text, 'denied'::text, 'failed'::text, 'skipped'::text]))),
    CONSTRAINT action_calls_pkey PRIMARY KEY (id),
    CONSTRAINT action_calls_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE,
    CONSTRAINT action_calls_target_id_fkey FOREIGN KEY (target_id) REFERENCES action_targets(id) ON DELETE CASCADE
);
CREATE INDEX action_calls_created ON action_calls USING btree (created_at);
CREATE INDEX action_calls_environment ON action_calls USING btree (environment_id, id DESC);
CREATE INDEX action_calls_target ON action_calls USING btree (target_id, id DESC);

CREATE TABLE usage_daily (
    environment_id uuid NOT NULL,
    day date NOT NULL,
    metric text NOT NULL,
    count bigint DEFAULT 0 NOT NULL,
    CONSTRAINT usage_daily_count_check CHECK ((count >= 0)),
    CONSTRAINT usage_daily_metric_check CHECK ((metric ~ '^[a-z][a-z_]{0,31}$'::text)),
    CONSTRAINT usage_daily_pkey PRIMARY KEY (environment_id, day, metric),
    CONSTRAINT usage_daily_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);
CREATE INDEX usage_daily_day ON usage_daily USING btree (day);

-- Single row: the last event the usage rollup consumed.
CREATE TABLE usage_rollup_cursor (
    id boolean DEFAULT true NOT NULL,
    event_id bigint NOT NULL,
    CONSTRAINT usage_rollup_cursor_id_check CHECK (id),
    CONSTRAINT usage_rollup_cursor_pkey PRIMARY KEY (id)
);

INSERT INTO usage_rollup_cursor (id, event_id) VALUES (true, 0);
