-- Phone verification (U5).
--
-- A user verifies a phone number they type themselves: the number and a
-- hashed 6-digit code wait here until the code is entered, then become
-- users.phone with phone_verified = true. One pending number per user; a
-- new one replaces it. attempts counts wrong entries of the current code;
-- codes_sent counts codes sent since codes_window, to cap sends per hour.
CREATE TABLE phone_verifications (
  user_id        uuid        PRIMARY KEY,
  environment_id uuid        NOT NULL,
  phone          text        NOT NULL CHECK (phone ~ '^\+[1-9][0-9]{6,14}$'),
  code_hash      bytea,
  expires_at     timestamptz,
  sent_at        timestamptz NOT NULL,
  attempts       int         NOT NULL DEFAULT 0,
  codes_sent     int         NOT NULL DEFAULT 0,
  codes_window   timestamptz NOT NULL,
  FOREIGN KEY (user_id, environment_id) REFERENCES users(id, environment_id) ON DELETE CASCADE
);
CREATE TRIGGER phone_verifications_human BEFORE INSERT ON phone_verifications
  FOR EACH ROW EXECUTE FUNCTION refuse_machine_user();

-- Only a number can be verified (operators may now set the flag).
UPDATE users SET phone_verified = false WHERE phone = '' AND phone_verified;
ALTER TABLE users ADD CONSTRAINT users_phone_verified CHECK (phone <> '' OR NOT phone_verified);

-- A provisioning connection maps SCIM phoneNumbers[type eq "mobile"] to
-- users.phone only when it opts in, so existing directories never clear
-- phone numbers users or operators set.
ALTER TABLE provisioning_connections
  ADD COLUMN map_phone boolean NOT NULL DEFAULT false;
