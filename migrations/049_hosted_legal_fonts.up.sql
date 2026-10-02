-- Hosted fonts, legal links and terms acceptance (L4). Fonts live in the
-- theme JSON (theme.font / theme.heading_font), so they need no column.
-- legal holds privacy_url, terms_url, help_url and support_email; a client
-- style's empty fields inherit the environment's. With require_terms,
-- sign-up asks to accept the terms; the acceptance time is kept on the
-- pending sign-up and then on the user.
ALTER TABLE login_settings ADD COLUMN legal jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(legal) = 'object' AND length(legal::text) <= 8192);
ALTER TABLE client_login_settings ADD COLUMN legal jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(legal) = 'object' AND length(legal::text) <= 8192);
ALTER TABLE sign_in_policies ADD COLUMN require_terms boolean NOT NULL DEFAULT false;
ALTER TABLE signups ADD COLUMN terms_accepted_at timestamptz;
ALTER TABLE users ADD COLUMN terms_accepted_at timestamptz;
