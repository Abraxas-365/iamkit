-- 021: email and SMS codes as second factors, phone numbers, SMS delivery.
--
-- An email or SMS factor holds at most one live code: its hash, when it
-- expires and when it was sent (a new code replaces the previous one).
-- code_attempts counts wrong entries of that code; codes_sent counts codes
-- sent since codes_window, to cap sends per hour.
-- An SMS factor keeps its phone number in data->>'phone'.
ALTER TABLE user_factors
  ADD COLUMN code_hash       bytea,
  ADD COLUMN code_expires_at timestamptz,
  ADD COLUMN code_sent_at    timestamptz,
  ADD COLUMN code_attempts   int NOT NULL DEFAULT 0,
  ADD COLUMN codes_sent      int NOT NULL DEFAULT 0,
  ADD COLUMN codes_window    timestamptz;

-- A user's phone number (E.164); phone_verified once an SMS code sent to it
-- was entered. Changing the number clears phone_verified.
ALTER TABLE users
  ADD COLUMN phone          text    NOT NULL DEFAULT '' CHECK (phone = '' OR phone ~ '^\+[1-9][0-9]{6,14}$'),
  ADD COLUMN phone_verified boolean NOT NULL DEFAULT false;

-- Which second factors users may use. Email and SMS codes are opt-in for the
-- environment, so existing email webhooks never receive the new "mfa"
-- purpose unless an operator allows it. Organizations narrow the list.
ALTER TABLE sign_in_policies
  ADD COLUMN allowed_factors text[] NOT NULL DEFAULT '{totp,webauthn}'
    CHECK (allowed_factors <@ ARRAY['totp','email','sms','webauthn']);
ALTER TABLE organizations
  ADD COLUMN allowed_factors text[] NOT NULL DEFAULT '{totp,email,sms,webauthn}'
    CHECK (allowed_factors <@ ARRAY['totp','email','sms','webauthn']);

-- Emails of the new purpose "mfa" (second-factor code).
ALTER TABLE email_templates DROP CONSTRAINT email_templates_purpose_check,
  ADD CONSTRAINT email_templates_purpose_check
    CHECK (purpose IN ('login','password_reset','email_verification','invitation','test','mfa'));

-- Delivery activity per channel (email, sms).
ALTER TABLE delivery_activity
  ADD COLUMN channel text NOT NULL DEFAULT 'email' CHECK (channel IN ('email','sms')),
  DROP CONSTRAINT delivery_activity_purpose_check,
  ADD CONSTRAINT delivery_activity_purpose_check
    CHECK (purpose IN ('login','password_reset','email_verification','invitation','test','mfa','phone_verification')),
  DROP CONSTRAINT delivery_activity_failure_purpose_check,
  ADD CONSTRAINT delivery_activity_failure_purpose_check
    CHECK (failure_purpose IN ('login','password_reset','email_verification','invitation','test','mfa','phone_verification')),
  DROP CONSTRAINT delivery_activity_pkey,
  ADD PRIMARY KEY (environment_id, channel);

-- Per-environment SMS delivery: Twilio (account SID, sealed auth token, a
-- sender number or messaging service) or the customer's webhook (URL,
-- sealed signing token). A separate configuration from email, so email
-- webhooks never receive SMS messages.
CREATE TABLE sms_configs (
  environment_id        uuid        PRIMARY KEY REFERENCES environments(id),
  provider              text        NOT NULL CHECK (provider IN ('twilio','webhook')),
  account_sid           text        NOT NULL DEFAULT '',
  from_number           text        NOT NULL DEFAULT '',
  messaging_service_sid text        NOT NULL DEFAULT '',
  webhook_url           text        NOT NULL DEFAULT '',
  secret_sealed         text        NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  CHECK (
       (provider = 'twilio' AND account_sid <> '' AND (from_number <> '' OR messaging_service_sid <> '') AND webhook_url = '')
    OR (provider = 'webhook' AND webhook_url <> '' AND account_sid = '' AND from_number = '' AND messaging_service_sid = ''))
);
