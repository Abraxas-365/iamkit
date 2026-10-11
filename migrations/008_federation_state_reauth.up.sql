-- What an authorization asked of the upstream identity provider of a hosted
-- sign-in: prompt=login / max_age=0 (reauth) or max_age > 0 (max_age). The
-- callback refuses an ID token whose auth_time is older (fedsvc). started_at is
-- when the redirect was made.
ALTER TABLE federation_states
    ADD COLUMN reauth boolean DEFAULT false NOT NULL,
    ADD COLUMN max_age bigint,
    ADD COLUMN started_at timestamp with time zone DEFAULT now() NOT NULL,
    ADD CONSTRAINT federation_states_max_age CHECK (max_age IS NULL OR max_age >= 0);
