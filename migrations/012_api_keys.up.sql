-- Self-service API keys.
--
-- user_access_tokens (machine users' personal access tokens) becomes
-- api_keys, one credential for three owners:
--   user          a person's key in one organization (user_id set);
--   organization  the organization's own key (user_id NULL), survives its
--                 creator;
--   machine       a machine user's key (the former personal access token).
-- The value (ik_key_…) is shown once; only its hash and last four
-- characters are kept. Effective permissions are recomputed on every use:
-- user and organization keys = permissions ∩ the resource's allowlist for the
-- owner kind ∩ what the owner (user or organization) may do on the resource;
-- machine keys = permissions (NULL = all) ∩ the machine user's grants.
ALTER TABLE user_access_tokens RENAME TO api_keys;
ALTER TABLE api_keys RENAME CONSTRAINT user_access_tokens_name_check TO api_keys_name_check;
ALTER TABLE api_keys RENAME CONSTRAINT user_access_tokens_pkey TO api_keys_pkey;
ALTER TABLE api_keys RENAME CONSTRAINT user_access_tokens_id_environment_id_key TO api_keys_id_environment_id_key;
ALTER TABLE api_keys RENAME CONSTRAINT user_access_tokens_secret_hash_key TO api_keys_secret_hash_key;
ALTER TABLE api_keys RENAME CONSTRAINT user_access_tokens_environment_id_application_id_resource__fkey TO api_keys_application_resource_fkey;
ALTER TABLE api_keys RENAME CONSTRAINT user_access_tokens_organization_id_environment_id_fkey TO api_keys_organization_id_environment_id_fkey;
ALTER TABLE api_keys RENAME CONSTRAINT user_access_tokens_user_id_environment_id_fkey TO api_keys_user_id_environment_id_fkey;
ALTER INDEX user_access_tokens_user RENAME TO api_keys_user;

-- created_by_kind / created_by_id: who created the key (filled by the
-- api_key_creator trigger from created_by_id, like audit_event_context).
-- last4: the last four characters of the value (obfuscated_value).
ALTER TABLE api_keys
    ADD COLUMN owner_kind text DEFAULT 'machine'::text NOT NULL,
    ADD COLUMN permissions text[],
    ADD COLUMN created_by_kind text DEFAULT 'operator'::text NOT NULL,
    ADD COLUMN created_by_id uuid,
    ADD COLUMN last4 text DEFAULT ''::text NOT NULL;
ALTER TABLE api_keys ALTER COLUMN owner_kind DROP DEFAULT;
ALTER TABLE api_keys ALTER COLUMN user_id DROP NOT NULL;
-- application_id: machine keys only (their token exchange opens an
-- application session); user and organization keys are validated, never
-- exchanged, so they name only the resource.
ALTER TABLE api_keys ALTER COLUMN application_id DROP NOT NULL;
ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_resource_fkey FOREIGN KEY (resource_id, environment_id) REFERENCES resources(id, environment_id) ON DELETE CASCADE,
    ADD CONSTRAINT api_keys_application CHECK (((owner_kind = 'machine'::text) = (application_id IS NOT NULL))),    ADD CONSTRAINT api_keys_owner_kind_check CHECK ((owner_kind = ANY (ARRAY['user'::text, 'organization'::text, 'machine'::text]))),
    ADD CONSTRAINT api_keys_owner_user CHECK (((owner_kind = 'organization'::text) = (user_id IS NULL))),
    ADD CONSTRAINT api_keys_permissions_check CHECK (((owner_kind = 'machine'::text) OR ((permissions IS NOT NULL) AND (cardinality(permissions) > 0)))),
    ADD CONSTRAINT api_keys_created_by_kind_check CHECK ((created_by_kind = ANY (ARRAY['operator'::text, 'user'::text, 'machine'::text, 'service_account'::text, 'setup_link'::text, 'system'::text]))),
    ADD CONSTRAINT api_keys_last4_check CHECK ((length(last4) <= 4));
CREATE INDEX api_keys_organization ON api_keys USING btree (environment_id, organization_id, created_at DESC);

-- Existing tokens: their creator is the actor of their audit row.
UPDATE api_keys k
   SET created_by_id = a.actor_id, created_by_kind = a.actor_kind
  FROM (SELECT DISTINCT ON (split_part(target_id, '?', 1)) split_part(target_id, '?', 1) AS key_id, actor_id, actor_kind
          FROM audit_events
         WHERE action = 'user.access_token_created'
         ORDER BY split_part(target_id, '?', 1), id) a
 WHERE a.key_id = k.id::text
   AND a.actor_kind = ANY (ARRAY['operator', 'user', 'service_account', 'setup_link', 'system']);

CREATE FUNCTION api_key_creator() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.created_by_id IS NULL THEN
        NEW.created_by_kind := 'system';
    ELSIF EXISTS (SELECT 1 FROM users WHERE id = NEW.created_by_id AND environment_id = NEW.environment_id AND kind = 'machine') THEN
        NEW.created_by_kind := 'machine';
    ELSIF EXISTS (SELECT 1 FROM users WHERE id = NEW.created_by_id AND environment_id = NEW.environment_id) THEN
        NEW.created_by_kind := 'user';
    ELSIF EXISTS (SELECT 1 FROM service_accounts WHERE id = NEW.created_by_id AND environment_id = NEW.environment_id) THEN
        NEW.created_by_kind := 'service_account';
    ELSIF EXISTS (SELECT 1 FROM org_setup_links WHERE id = NEW.created_by_id AND environment_id = NEW.environment_id) THEN
        NEW.created_by_kind := 'setup_link';
    ELSE
        NEW.created_by_kind := 'operator';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER api_key_creator BEFORE INSERT ON api_keys
  FOR EACH ROW
  EXECUTE FUNCTION api_key_creator();

-- Sessions exchanged from a machine key (/identity/v1/token-exchange).
ALTER TABLE sessions RENAME COLUMN access_token_id TO api_key_id;
ALTER TABLE sessions RENAME CONSTRAINT sessions_access_token_id_fkey TO sessions_api_key_id_fkey;
ALTER INDEX sessions_access_token RENAME TO sessions_api_key;

-- A membership that ends (deactivated or removed) revokes the member's user
-- and machine keys in that organization (event api_key.revoked, actor
-- system, data.reason membership_ended); re-adding the member does not bring
-- them back.
CREATE FUNCTION revoke_member_api_keys() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    WITH revoked AS (
        UPDATE api_keys SET revoked_at = now()
         WHERE environment_id = OLD.environment_id AND organization_id = OLD.organization_id
           AND user_id = OLD.user_id AND revoked_at IS NULL
        RETURNING id, environment_id, organization_id, user_id, owner_kind, resource_id)
    INSERT INTO events (environment_id, type, actor_kind, actor_id, subject_kind, subject_id, organization_id, data)
    SELECT r.environment_id, 'api_key.revoked', 'system', '', 'api_key', r.id::text, r.organization_id,
           jsonb_build_object('owner_type', r.owner_kind, 'user_id', r.user_id, 'organization_id', r.organization_id,
                              'resource_id', r.resource_id, 'reason', 'membership_ended')
      FROM revoked r;
    RETURN NULL;
END $$;
CREATE TRIGGER membership_api_keys_ended AFTER UPDATE ON memberships
  FOR EACH ROW WHEN ((old.active AND NOT new.active))
  EXECUTE FUNCTION revoke_member_api_keys();
CREATE TRIGGER membership_api_keys_removed AFTER DELETE ON memberships
  FOR EACH ROW
  EXECUTE FUNCTION revoke_member_api_keys();

-- Per-resource allowlists (WorkOS-style): the permissions user keys and
-- organization keys may carry on the resource. Empty = no key of that owner
-- kind for the resource. Never on the IAM resource: IAMKit's own API is
-- reached with the customer's own credential (service account or machine
-- user), not with its users' or organizations' keys. Removing a permission
-- from the resource removes it from both lists (api_key_allowlists).
ALTER TABLE resources
    ADD COLUMN api_key_user_permissions text[] DEFAULT '{}'::text[] NOT NULL,
    ADD COLUMN api_key_organization_permissions text[] DEFAULT '{}'::text[] NOT NULL;
ALTER TABLE resources
    ADD CONSTRAINT resources_api_key_user_permissions_check CHECK ((api_key_user_permissions <@ permissions)),
    ADD CONSTRAINT resources_api_key_organization_permissions_check CHECK ((api_key_organization_permissions <@ permissions)),
    ADD CONSTRAINT resources_api_key_iam CHECK (((prefix <> 'iam'::text) OR ((cardinality(api_key_user_permissions) = 0) AND (cardinality(api_key_organization_permissions) = 0))));

CREATE FUNCTION api_key_allowlists() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.api_key_user_permissions := ARRAY(SELECT p FROM unnest(NEW.api_key_user_permissions) p WHERE p = ANY (NEW.permissions));
    NEW.api_key_organization_permissions := ARRAY(SELECT p FROM unnest(NEW.api_key_organization_permissions) p WHERE p = ANY (NEW.permissions));
    RETURN NEW;
END $$;
CREATE TRIGGER api_key_allowlists BEFORE UPDATE OF permissions ON resources
  FOR EACH ROW
  EXECUTE FUNCTION api_key_allowlists();

-- api_key_reach: what an owner may do on a resource now. A user (p_user
-- set): their effective_grants in the organization. An organization
-- (p_user NULL): every permission of the resource when it needs no grant,
-- or the organization owns it or holds a grant of every role; else the
-- permissions of the roles it was granted.
CREATE FUNCTION api_key_reach(p_environment uuid, p_organization uuid, p_user uuid, p_resource uuid) RETURNS text[]
    LANGUAGE sql STABLE
    AS $$
  SELECT CASE WHEN p_user IS NOT NULL THEN
      coalesce((SELECT g.permissions FROM effective_grants g
                 WHERE g.environment_id = p_environment AND g.organization_id = p_organization
                   AND g.user_id = p_user AND g.resource_id = p_resource), '{}')
    ELSE coalesce((
      SELECT CASE WHEN NOT r.require_grant OR r.owner_organization_id = p_organization
                    OR EXISTS (SELECT 1 FROM resource_grants rg WHERE rg.resource_id = r.id
                                  AND rg.organization_id = p_organization AND rg.role_ids IS NULL)
               THEN r.permissions
               ELSE coalesce((SELECT array_agg(DISTINCT p) FROM resource_grants rg
                               JOIN roles ro ON ro.id = ANY (rg.role_ids)
                               CROSS JOIN LATERAL unnest(ro.permissions) p
                              WHERE rg.resource_id = r.id AND rg.organization_id = p_organization), '{}')
             END
        FROM resources r WHERE r.id = p_resource AND r.environment_id = p_environment), '{}')
    END
$$;

-- api_key_permissions: a key's effective permissions now. Machine keys:
-- the machine user's reach, narrowed to the key's list when it has one.
-- User and organization keys: the key's list ∩ the resource's allowlist for
-- the owner kind ∩ the owner's reach. Creation checks call it with the
-- requested list, so a key is never created wider than it would act.
CREATE FUNCTION api_key_permissions(p_owner_kind text, p_permissions text[], p_environment uuid, p_organization uuid, p_user uuid, p_resource uuid) RETURNS text[]
    LANGUAGE sql STABLE
    AS $$
  SELECT coalesce(array_agg(p ORDER BY p), '{}') FROM (
    SELECT DISTINCT p FROM unnest(api_key_reach(p_environment, p_organization, p_user, p_resource)) p
     WHERE (p_permissions IS NULL AND p_owner_kind = 'machine') OR p = ANY (p_permissions)
    INTERSECT
    SELECT p FROM resources r,
           unnest(CASE p_owner_kind WHEN 'user' THEN r.api_key_user_permissions
                                    WHEN 'organization' THEN r.api_key_organization_permissions
                                    ELSE r.permissions END) p
     WHERE r.id = p_resource AND r.environment_id = p_environment
  ) allowed
$$;

-- The environment's API key policy (no row = defaults: user and
-- organization keys off, no maximum lifetime, 10 live keys per user per
-- organization, 50 live organization keys per organization). Turning a kind
-- off also stops its existing keys from validating. Machine keys are
-- operator credentials and ignore it.
CREATE TABLE api_key_policies (
    environment_id uuid NOT NULL,
    user_keys boolean DEFAULT false NOT NULL,
    organization_keys boolean DEFAULT false NOT NULL,
    max_ttl_days integer,
    max_per_user integer DEFAULT 10 NOT NULL,
    max_per_organization integer DEFAULT 50 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT api_key_policies_max_ttl_days_check CHECK (((max_ttl_days IS NULL) OR ((max_ttl_days >= 1) AND (max_ttl_days <= 365)))),
    CONSTRAINT api_key_policies_max_per_user_check CHECK (((max_per_user >= 1) AND (max_per_user <= 100))),
    CONSTRAINT api_key_policies_max_per_organization_check CHECK (((max_per_organization >= 1) AND (max_per_organization <= 500))),
    CONSTRAINT api_key_policies_pkey PRIMARY KEY (environment_id),
    CONSTRAINT api_key_policies_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);

-- New IAM resource permissions (authorization.IAMResourcePermissions):
-- iam:api-keys:read / :write (operators' and service accounts' view of every
-- key, the policy), and the organization-bound iam:org:api-keys:read /
-- :write (organization keys and members' keys). org_owner holds every
-- organization permission, so it gains the organization ones.
UPDATE resources
   SET permissions = permissions || ARRAY(
         SELECT p FROM unnest(ARRAY['iam:api-keys:read', 'iam:api-keys:write', 'iam:org:api-keys:read', 'iam:org:api-keys:write']) AS p
          WHERE NOT (p = ANY (permissions)))
 WHERE prefix = 'iam';
-- role_updated would end every live session of every owner; tokens pick the
-- permissions up at their next sign-in instead.
ALTER TABLE roles DISABLE TRIGGER role_updated;
UPDATE roles
   SET permissions = permissions || ARRAY(
         SELECT p FROM unnest(ARRAY['iam:org:api-keys:read', 'iam:org:api-keys:write']) AS p
          WHERE NOT (p = ANY (permissions)))
 WHERE system_role = 'org_owner';
ALTER TABLE roles ENABLE TRIGGER role_updated;

-- A new actor kind: machine (a machine user acting with its key or a token
-- exchanged from it); its id is the machine user's.
ALTER TABLE audit_events DROP CONSTRAINT audit_events_actor_kind_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_actor_kind_check
    CHECK ((actor_kind = ANY (ARRAY['operator'::text, 'user'::text, 'machine'::text, 'service_account'::text, 'setup_link'::text, 'system'::text])));
ALTER TABLE events DROP CONSTRAINT events_actor_kind_check;
ALTER TABLE events ADD CONSTRAINT events_actor_kind_check
    CHECK ((actor_kind = ANY (ARRAY['operator'::text, 'user'::text, 'machine'::text, 'service_account'::text, 'directory'::text, 'setup_link'::text, 'system'::text])));

CREATE OR REPLACE FUNCTION audit_event_context() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE id = NEW.actor_id AND environment_id = NEW.environment_id AND kind = 'machine') THEN
        NEW.actor_kind := 'machine';
    ELSIF EXISTS (SELECT 1 FROM users WHERE id = NEW.actor_id AND environment_id = NEW.environment_id) THEN
        NEW.actor_kind := 'user';
    ELSIF EXISTS (SELECT 1 FROM service_accounts WHERE id = NEW.actor_id AND environment_id = NEW.environment_id) THEN
        NEW.actor_kind := 'service_account';
    ELSIF EXISTS (SELECT 1 FROM org_setup_links WHERE id = NEW.actor_id AND environment_id = NEW.environment_id) THEN
        NEW.actor_kind := 'setup_link';
    END IF;
    IF NEW.organization_id IS NULL THEN
        NEW.organization_id := substring(NEW.target_id FROM '/organizations/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')::uuid;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION event_actor() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
BEGIN
  IF NEW.actor_kind IS NULL THEN
    IF NEW.actor_id = '' THEN
      NEW.actor_kind := 'system';
    ELSIF NEW.actor_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND EXISTS (SELECT 1 FROM users WHERE id = NEW.actor_id::uuid AND environment_id = NEW.environment_id AND kind = 'machine') THEN
      NEW.actor_kind := 'machine';
    ELSIF NEW.actor_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND EXISTS (SELECT 1 FROM users WHERE id = NEW.actor_id::uuid AND environment_id = NEW.environment_id) THEN
      NEW.actor_kind := 'user';
    ELSIF NEW.actor_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND EXISTS (SELECT 1 FROM service_accounts WHERE id = NEW.actor_id::uuid AND environment_id = NEW.environment_id) THEN
      NEW.actor_kind := 'service_account';
    ELSIF NEW.actor_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND EXISTS (SELECT 1 FROM provisioning_credentials WHERE id = NEW.actor_id::uuid AND environment_id = NEW.environment_id) THEN
      NEW.actor_kind := 'directory';
    ELSIF NEW.actor_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
      AND EXISTS (SELECT 1 FROM org_setup_links WHERE id = NEW.actor_id::uuid AND environment_id = NEW.environment_id) THEN
      NEW.actor_kind := 'setup_link';
    ELSE
      NEW.actor_kind := 'operator';
    END IF;
  END IF;
  RETURN NEW;
END $_$;
