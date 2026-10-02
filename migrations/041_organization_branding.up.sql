-- Organization branding (B3): an organization's overrides of the hosted
-- pages and invitation emails. Every column is nullable: NULL inherits the
-- client style or environment default underneath (field-level merge,
-- environment ← client ← organization). theme replaces the whole theme
-- block when set. There is no language: emails keep the environment's.
CREATE TABLE organization_login_settings (
  organization_id uuid PRIMARY KEY,
  environment_id  uuid NOT NULL,
  display_name    text,
  logo_url        text,
  accent_color    text CHECK (accent_color IS NULL OR accent_color ~ '^#[0-9a-f]{6}$'),
  theme           jsonb,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (organization_id, environment_id) REFERENCES organizations(id, environment_id) ON DELETE CASCADE
);
CREATE INDEX organization_login_settings_environment ON organization_login_settings(environment_id);
