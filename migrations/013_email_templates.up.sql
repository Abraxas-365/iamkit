-- Customized wording of the emails IAMKit renders (SMTP, Resend), per
-- environment, purpose and language. Only the wording is stored: the layout
-- (logo, code box, button, link fallback) stays IAMKit's, so a template can
-- never drop the code or the link. An empty field keeps IAMKit's default
-- for that field; no row keeps every default. Lengths are in characters,
-- as validated in Go (which also checks placeholders and languages).
CREATE TABLE email_templates (
  environment_id uuid NOT NULL REFERENCES environments(id),
  purpose    text NOT NULL CHECK (purpose IN ('login','password_reset','email_verification','invitation','test')),
  locale     text NOT NULL CHECK (length(locale) BETWEEN 2 AND 16),
  subject    text NOT NULL DEFAULT '' CHECK (char_length(subject) <= 200),
  heading    text NOT NULL DEFAULT '' CHECK (char_length(heading) <= 200),
  body       text NOT NULL DEFAULT '' CHECK (char_length(body) <= 2000),
  action     text NOT NULL DEFAULT '' CHECK (char_length(action) <= 60),
  footer     text NOT NULL DEFAULT '' CHECK (char_length(footer) <= 500),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (environment_id, purpose, locale),
  -- Only invitations have a button.
  CHECK (action = '' OR purpose = 'invitation'),
  -- A row customizes something; resetting deletes it.
  CHECK (subject <> '' OR heading <> '' OR body <> '' OR action <> '' OR footer <> '')
);
