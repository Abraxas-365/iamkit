-- Avatars: an https URL to the user's picture (IAMKit stores no images).
-- '' = none. Set by operators, the user (/identity/v1/me) or a federation
-- provider's picture claim; released as the OIDC `picture` claim.
ALTER TABLE users ADD COLUMN avatar_url text NOT NULL DEFAULT ''
  CHECK (length(avatar_url) <= 2048);
