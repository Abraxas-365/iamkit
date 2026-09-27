-- Hosted page themes (mode, colors, header/footer, favicon) and per-client
-- styles. A client style is complete (copied from the environment default
-- when created) and falls back to the default only when absent.
ALTER TABLE login_settings ADD COLUMN theme jsonb NOT NULL DEFAULT '{}';

CREATE TABLE client_login_settings (
  client_id      uuid PRIMARY KEY,
  environment_id uuid NOT NULL,
  display_name   text NOT NULL DEFAULT '',
  logo_url       text NOT NULL DEFAULT '',
  accent_color   text NOT NULL DEFAULT '' CHECK (accent_color = '' OR accent_color ~ '^#[0-9a-f]{6}$'),
  theme          jsonb NOT NULL DEFAULT '{}',
  updated_at     timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (client_id, environment_id) REFERENCES oauth_clients(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX client_login_settings_environment ON client_login_settings(environment_id);
