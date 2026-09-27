-- Email delivery providers and email language.
--
-- provider selects how an environment sends email: the customer's webhook
-- (the original behaviour, which writes the email itself), or SMTP / Resend,
-- for which IAMKit renders the email. secret_sealed holds the SMTP password
-- or Resend API key sealed with IAMKIT_ENCRYPTION_KEY; the webhook token
-- stays in webhook_token. Only the columns of the chosen provider are set.
ALTER TABLE delivery_configs
  ADD COLUMN provider      text NOT NULL DEFAULT 'webhook'
    CHECK (provider IN ('webhook','smtp','resend')),
  ADD COLUMN from_email    text NOT NULL DEFAULT '',
  ADD COLUMN from_name     text NOT NULL DEFAULT '' CHECK (length(from_name) <= 100),
  ADD COLUMN reply_to      text NOT NULL DEFAULT '',
  ADD COLUMN smtp_host     text NOT NULL DEFAULT '',
  ADD COLUMN smtp_port     int CHECK (smtp_port BETWEEN 1 AND 65535),
  ADD COLUMN smtp_username text NOT NULL DEFAULT '',
  ADD COLUMN smtp_tls      text NOT NULL DEFAULT '' CHECK (smtp_tls IN ('','starttls','tls')),
  ADD COLUMN secret_sealed text NOT NULL DEFAULT '',
  ALTER COLUMN webhook_url   SET DEFAULT '',
  ALTER COLUMN webhook_token SET DEFAULT '';

ALTER TABLE delivery_configs ADD CONSTRAINT delivery_configs_provider_settings CHECK (
     (provider = 'webhook' AND webhook_url <> '' AND webhook_token <> ''
       AND from_email = '' AND smtp_host = '' AND smtp_port IS NULL AND secret_sealed = '')
  OR (provider = 'smtp' AND from_email <> '' AND smtp_host <> '' AND smtp_port IS NOT NULL
       AND smtp_tls <> '' AND webhook_url = '' AND webhook_token = '')
  OR (provider = 'resend' AND from_email <> '' AND secret_sealed <> ''
       AND smtp_host = '' AND smtp_port IS NULL AND webhook_url = '' AND webhook_token = ''));

-- Default language of the emails IAMKit writes for the environment ('' =
-- server default). Codes are validated in Go against the i18n catalogs.
ALTER TABLE login_settings ADD COLUMN locale text NOT NULL DEFAULT '' CHECK (length(locale) <= 16);
