-- Machine users and personal access tokens (U6).
--
-- A machine user is a user of kind 'machine': it joins organizations and
-- receives roles, groups and grants like any user, but has no email,
-- username, password, phone or second factor, so no sign-in path (all of
-- which look users up by email or username) can ever match it. It
-- authenticates with personal access tokens.

ALTER TABLE users
    ADD COLUMN kind text NOT NULL DEFAULT 'human' CHECK (kind IN ('human', 'machine')),
    ALTER COLUMN email DROP NOT NULL,
    ADD CONSTRAINT users_kind_credentials CHECK (
        (kind = 'human' AND email IS NOT NULL)
        OR (kind = 'machine' AND email IS NULL AND username IS NULL AND password_hash = ''
            AND NOT otp_enabled AND NOT email_verified AND phone = ''));

-- Machine users never get sign-in credentials: second factors, linked
-- external identities, emailed challenges or SCIM identities. Raised as a
-- foreign key violation, so writers answer "user not found".
CREATE FUNCTION refuse_machine_user() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE id = NEW.user_id AND environment_id = NEW.environment_id AND kind = 'machine') THEN
        RAISE EXCEPTION 'machine users cannot have sign-in credentials' USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER user_factors_human BEFORE INSERT ON user_factors
    FOR EACH ROW EXECUTE FUNCTION refuse_machine_user();
CREATE TRIGGER external_identities_human BEFORE INSERT ON external_identities
    FOR EACH ROW EXECUTE FUNCTION refuse_machine_user();
CREATE TRIGGER identity_challenges_human BEFORE INSERT ON identity_challenges
    FOR EACH ROW EXECUTE FUNCTION refuse_machine_user();
CREATE TRIGGER provisioned_identities_human BEFORE INSERT ON provisioned_identities
    FOR EACH ROW EXECUTE FUNCTION refuse_machine_user();

-- A personal access token (ik_pat_, only its SHA-256 is stored) acts as the
-- machine user in one organization for one application resource, with the
-- user's live permissions there. Revoked tokens stay listed.
CREATE TABLE user_access_tokens (
    id              uuid        PRIMARY KEY,
    environment_id  uuid        NOT NULL,
    user_id         uuid        NOT NULL,
    organization_id uuid        NOT NULL,
    application_id  uuid        NOT NULL,
    resource_id     uuid        NOT NULL,
    name            text        NOT NULL CHECK (length(trim(name)) > 0),
    secret_hash     bytea       NOT NULL UNIQUE,
    expires_at      timestamptz NOT NULL,
    last_used_at    timestamptz,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, environment_id),
    FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE,
    FOREIGN KEY (environment_id, application_id, resource_id)
        REFERENCES application_resources(environment_id, application_id, resource_id)
);
CREATE INDEX user_access_tokens_user ON user_access_tokens(environment_id, user_id, created_at DESC);

-- Sessions opened by exchanging a token end when it is revoked.
ALTER TABLE sessions
    ADD COLUMN access_token_id uuid REFERENCES user_access_tokens(id) ON DELETE CASCADE;
CREATE INDEX sessions_access_token ON sessions(access_token_id) WHERE access_token_id IS NOT NULL;
