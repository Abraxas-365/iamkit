-- Sign-up waitlist (opt-in per environment): people who ask for an account
-- wait for an operator's decision before the normal verified sign-up.
CREATE TABLE waitlist_entries (
    id uuid NOT NULL,
    environment_id uuid NOT NULL,
    email text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    locale text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    decided_at timestamp with time zone,
    decided_by text DEFAULT ''::text NOT NULL,
    -- End of the approval: the sign-up link stops working after it.
    expires_at timestamp with time zone,
    -- SHA-256 of the ik_wait_ token the approval email carries.
    token_hash bytea,
    completed_user_id uuid,
    CONSTRAINT waitlist_entries_pkey PRIMARY KEY (id),
    CONSTRAINT waitlist_entries_id_environment_id_key UNIQUE (id, environment_id),
    CONSTRAINT waitlist_entries_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text, 'completed'::text]))),
    CONSTRAINT waitlist_entries_email_check CHECK (((length(email) >= 3) AND (length(email) <= 320) AND (email = lower(email)))),
    CONSTRAINT waitlist_entries_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
);

-- One open entry per address: a rejected entry keeps the address out (joining
-- again is silently ignored) until an operator deletes it; a completed entry
-- does not block (the account may be deleted and ask again).
CREATE UNIQUE INDEX waitlist_entries_live_email ON waitlist_entries USING btree (environment_id, email) WHERE (status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text]));
CREATE INDEX waitlist_entries_list ON waitlist_entries USING btree (environment_id, status, created_at DESC, id);
CREATE UNIQUE INDEX waitlist_entries_token ON waitlist_entries USING btree (token_hash) WHERE (token_hash IS NOT NULL);

ALTER TABLE sign_in_policies
    ADD COLUMN waitlist boolean DEFAULT false NOT NULL,
    ADD COLUMN waitlist_auto_approve_domains text[] DEFAULT '{}'::text[] NOT NULL,
    -- Where the approval email's link points (the application's sign-up
    -- page; ?waitlist=<token> is appended). Empty: IAMKit's hosted page.
    ADD COLUMN waitlist_signup_url text DEFAULT ''::text NOT NULL;

-- A sign-up started with an approval token remembers its entry, so the
-- account's creation can complete it in the same transaction.
ALTER TABLE signups ADD COLUMN waitlist_entry_id uuid;

-- New IAM resource permissions: iam:waitlist:read / :write. No role or
-- service account gains them.
UPDATE resources
   SET permissions = permissions || ARRAY(
         SELECT p FROM unnest(ARRAY['iam:waitlist:read', 'iam:waitlist:write']) AS p
          WHERE NOT (p = ANY (permissions)))
 WHERE prefix = 'iam';

-- Wording overrides for the waitlist emails (waitlist_approved has a button;
-- security_alert was missing from the list too).
ALTER TABLE email_templates DROP CONSTRAINT email_templates_purpose_check;
ALTER TABLE email_templates ADD CONSTRAINT email_templates_purpose_check CHECK ((purpose = ANY (ARRAY['login'::text, 'password_reset'::text, 'email_verification'::text, 'invitation'::text, 'test'::text, 'mfa'::text, 'security_alert'::text, 'waitlist_joined'::text, 'waitlist_approved'::text, 'waitlist_rejected'::text])));
ALTER TABLE email_templates DROP CONSTRAINT email_templates_check;
ALTER TABLE email_templates ADD CONSTRAINT email_templates_check CHECK (((action = ''::text) OR (purpose = ANY (ARRAY['invitation'::text, 'waitlist_approved'::text]))));
