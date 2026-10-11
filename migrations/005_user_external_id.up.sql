-- Users: an optional external ID, the identifier the operator's own system
-- uses for the user (billing, CRM, HR). Unique per environment; machine users
-- may have one too. Not a SCIM externalId (those live in
-- provisioned_identities) and never released in tokens. The record_changes
-- trigger on users already diffs it into the event history.
ALTER TABLE users ADD COLUMN external_id text;
ALTER TABLE users ADD CONSTRAINT users_external_id_check CHECK (external_id = btrim(external_id) AND char_length(external_id) BETWEEN 1 AND 255);
CREATE UNIQUE INDEX users_environment_external_id ON users USING btree (environment_id, external_id) WHERE (external_id IS NOT NULL);
