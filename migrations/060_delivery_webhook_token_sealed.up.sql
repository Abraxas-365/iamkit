-- 060: The delivery webhook token is sealed at rest (J9 secrets, F-061).
--
-- With IAMKIT_ENCRYPTION_KEY the token is stored in secret_sealed like the
-- SMTP password and Resend API key; without a key (or in rows saved before)
-- it stays in webhook_token. A webhook row has exactly one of the two.
ALTER TABLE delivery_configs DROP CONSTRAINT IF EXISTS delivery_configs_provider_settings;
ALTER TABLE delivery_configs ADD CONSTRAINT delivery_configs_provider_settings CHECK (
     (provider = 'webhook' AND webhook_url <> '' AND (webhook_token = '') <> (secret_sealed = '')
       AND from_email = '' AND smtp_host = '' AND smtp_port IS NULL)
  OR (provider = 'smtp' AND from_email <> '' AND smtp_host <> '' AND smtp_port IS NOT NULL
       AND smtp_tls <> '' AND webhook_url = '' AND webhook_token = '')
  OR (provider = 'resend' AND from_email <> '' AND secret_sealed <> ''
       AND smtp_host = '' AND smtp_port IS NULL AND webhook_url = '' AND webhook_token = ''));
