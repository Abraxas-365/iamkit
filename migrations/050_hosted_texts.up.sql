-- Custom sign-in texts (L3): operators reword any hosted page text
-- (catalog keys under "hosted.") per language for the environment, one
-- OAuth client or one organization. Pages resolve each key organization ←
-- client ← environment ← catalog(page language) ← catalog(en). Email
-- wording keeps email_templates. texts maps keys to plain-text messages
-- (validated by the service: known keys, length, placeholders).
CREATE TABLE hosted_texts (
  environment_id  uuid NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
  client_id       uuid,
  organization_id uuid,
  locale          text NOT NULL CHECK (locale ~ '^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$'),
  texts           jsonb NOT NULL CHECK (jsonb_typeof(texts) = 'object' AND length(texts::text) <= 262144),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  CHECK (client_id IS NULL OR organization_id IS NULL),
  FOREIGN KEY (client_id, environment_id) REFERENCES oauth_clients(id, environment_id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX hosted_texts_scope ON hosted_texts (
  environment_id,
  COALESCE(client_id, '00000000-0000-0000-0000-000000000000'),
  COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'),
  locale
);
