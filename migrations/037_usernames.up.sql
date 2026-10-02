-- Optional usernames (U3): a second sign-in identifier, unique per
-- environment. Stored normalized (lowercase) and never containing '@', so a
-- sign-in input is an email exactly when it has one.
ALTER TABLE users ADD COLUMN username text
    CHECK (username = lower(username) AND username ~ '^[a-z0-9][a-z0-9._-]{2,63}$');

CREATE UNIQUE INDEX users_environment_username ON users(environment_id, username) WHERE username IS NOT NULL;
