-- Hosted page languages (L1). login_settings.languages narrows the
-- languages hosted pages may use (empty = every available one); clients and
-- organizations may pick their own default language: '' / NULL inherit the
-- environment's (organization NULL = the client's or environment's).
-- Organization languages also apply to invitation emails into it.
ALTER TABLE login_settings ADD COLUMN languages text[] NOT NULL DEFAULT '{}' CHECK (cardinality(languages) <= 64);
ALTER TABLE client_login_settings ADD COLUMN locale text NOT NULL DEFAULT '' CHECK (length(locale) <= 16);
ALTER TABLE organization_login_settings ADD COLUMN locale text CHECK (locale IS NULL OR length(locale) BETWEEN 2 AND 16);
